use std::{collections::{HashSet, VecDeque}, env, fs, io::Write, path::Path, sync::{Mutex, RwLock}, time::Duration};

use chrono::Local;
use crate::core::{game::Region, Hachimi, utils::get_masterdb_path};
use crate::il2cpp::ext::{Il2CppStringExt, StringExt};
use crate::il2cpp::hook::LibNative_Runtime::Sqlite3::{Connection, Query};
use crate::il2cpp::sql::find_meta_dress_ids;
use crate::il2cpp::symbols::{get_assembly_image, get_class, get_method_addr, Array};
use crate::il2cpp::types::{Il2CppArray, Il2CppImage, Il2CppObject, Il2CppString};
use once_cell::sync::Lazy;
use rusqlite::{Connection as RusqliteConnection, OpenFlags};
use serde_json::{json, Value};
use ureq;

static TIMEOUT: Lazy<Duration> = Lazy::new(|| {
    Duration::from_millis(Hachimi::instance().config.load().notifier_timeout_ms)
});
// https://github.com/algesten/ureq/issues/707
static AGENT: Lazy<ureq::Agent> = Lazy::new(|| {
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(*TIMEOUT))
        .timeout_recv_response(Some(*TIMEOUT))
        .timeout_send_body(Some(*TIMEOUT))
        .build();
    config.into()
});
static REQUEST: Lazy<String> = Lazy::new(|| Hachimi::instance().config.load().notifier_host.clone() + "/notify/request");
static RESPONSE: Lazy<String> = Lazy::new(|| Hachimi::instance().config.load().notifier_host.clone() + "/notify/response");
// FIFO queue of request URLs, popped by DecompressResponse in the same order Post pushed them.
// Cute.Http's task queue is serial, so Post (push) and DecompressResponse (pop) strictly
// alternate per request - unlike a single "last URL" global, this can't be clobbered by a
// later, unrelated request's Post() call racing ahead of the earlier response's decompression.
static POST_URL_QUEUE: Lazy<Mutex<VecDeque<String>>> = Lazy::new(|| Mutex::new(VecDeque::new()));
const POST_URL_QUEUE_CAPACITY: usize = 64;
// Request side: parks the uncompressed body produced by CompressRequest, keyed by the identity
// (pointer value) of the *compressed* array it returns. WWWRequest.Post receives that exact same
// compressed array as `post_data`, so matching on pointer identity (rather than call order) is
// exact - it can't be confused by concurrent/out-of-order requests the way a FIFO queue could.
static PENDING_REQUESTS: Lazy<Mutex<VecDeque<(usize, Vec<u8>)>>> = Lazy::new(|| Mutex::new(VecDeque::new()));
const PENDING_REQUEST_CAPACITY: usize = 64;
static UNLOCK_CHARA_IDS: Lazy<RwLock<Option<Vec<i32>>>> = Lazy::new(|| RwLock::new(None));
static UNLOCK_DRESS_IDS: Lazy<RwLock<Option<Vec<i32>>>> = Lazy::new(|| RwLock::new(None));
static UNLOCK_CARD_ROWS: Lazy<RwLock<Option<Vec<(i32, i32)>>>> = Lazy::new(|| RwLock::new(None));
static UNLOCK_DB_PATCHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
const RACE_URL_KEYWORDS: [&str; 3] = ["race_start", "race_replay", "get_saved_race_result"];

static mut BYTE_CLASS: *mut crate::il2cpp::types::Il2CppClass = 0 as _;

type CompressRequestFn = extern "C" fn(data: *mut Il2CppArray) -> *mut Il2CppArray;
type DecompressResponseFn = extern "C" fn(data: *mut Il2CppArray) -> *mut Il2CppArray;
type PostFn = extern "C" fn(
    this: *mut Il2CppObject,
    url: *mut Il2CppString,
    post_data: *mut Il2CppObject,
    headers: *mut Il2CppObject,
) -> *mut Il2CppObject;

extern "C" fn Post(
    this: *mut Il2CppObject,
    url: *mut Il2CppString,
    post_data: *mut Il2CppObject,
    headers: *mut Il2CppObject,
) -> *mut Il2CppObject {
    let game_url = unsafe { url.as_ref() }.map(|url_ref| url_ref.as_utf16str().to_string());

    if let Some(url_str) = &game_url {
        if let Ok(mut queue) = POST_URL_QUEUE.lock() {
            if queue.len() >= POST_URL_QUEUE_CAPACITY {
                queue.pop_front();
            }
            queue.push_back(url_str.clone());
        }
    }

    // Forward the request body here (not in CompressRequest) so it can be tagged with the URL,
    // which is only known at this point. Matched by exact pointer identity - see PENDING_REQUESTS.
    if let Some(body) = take_pending_request(post_data as usize) {
        if let Err(e) = post_with_url(REQUEST.as_str(), game_url.as_deref(), &body) {
            warn!("notifier: failed to forward request to '{}': {}", REQUEST.as_str(), e);
        }
    }

    get_orig_fn!(Post, PostFn)(this, url, post_data, headers)
}

/// Pops the URL of the request that corresponds to the response currently being decompressed.
/// See [`POST_URL_QUEUE`] for why this is FIFO instead of a single "last URL" value.
fn take_next_post_url() -> Option<String> {
    POST_URL_QUEUE.lock().ok().and_then(|mut queue| queue.pop_front())
}

/// Parks a request body produced by `CompressRequest`, keyed by the pointer identity of the
/// compressed array it returns (which `Post` receives verbatim as `post_data`).
fn queue_pending_request(compressed: usize, body: Vec<u8>) {
    let Ok(mut pending) = PENDING_REQUESTS.lock() else {
        return;
    };
    if pending.len() >= PENDING_REQUEST_CAPACITY {
        pending.pop_front();
    }
    pending.push_back((compressed, body));
}

/// Returns the parked body only on an exact pointer-identity match against `compressed`.
fn take_pending_request(compressed: usize) -> Option<Vec<u8>> {
    let mut pending = PENDING_REQUESTS.lock().ok()?;
    let index = pending.iter().position(|(ptr, _)| *ptr == compressed)?;
    pending.remove(index).map(|(_, body)| body)
}

/// Percent-encodes a header value so it's always a valid HTTP header (mirrors
/// hachimi-httpforward-plugin's encoding so downstream tools can decode it the same way).
fn header_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b' '..=b'~' => encoded.push(byte as char),
            _ => {
                use std::fmt::Write;
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

/// POSTs `body` to `url`, tagging it with an `X-Hachimi-Game-Url` header when available so the
/// receiver can route by URL directly instead of having to inspect/guess from the raw body.
fn post_with_url(url: &str, game_url: Option<&str>, body: &[u8]) -> Result<(), Box<ureq::Error>> {
    let mut request = AGENT.post(url);
    if let Some(game_url) = game_url {
        request = request.header("X-Hachimi-Game-Url", &header_value(game_url));
    }
    request.send(body)?;
    Ok(())
}

fn save_response_msgpack(data: &[u8], url: Option<&str>) {
    if !Hachimi::instance().config.load().enable_race_response_dump {
        return;
    }

    if !is_target_race_response_url(url) {
        return;
    }

    let hachimi = Hachimi::instance();
    let out_dir = hachimi.get_data_path("race");
    if let Err(e) = fs::create_dir_all(&out_dir) {
        warn!("Failed to create response dump dir {}: {}", out_dir.display(), e);
        return;
    }

    let now = Local::now();
    let url_suffix = current_url_suffix(url);
    let out_path = out_dir.join(format!(
        "{} {}.msgpack",
        now.format("%Y-%m-%d %H-%M-%S-%3f"),
        sanitize_filename_component(&url_suffix)
    ));

    if let Err(e) = fs::write(&out_path, data) {
        warn!("Failed to write response dump {}: {}", out_path.display(), e);
    }
}

fn save_circle_monthly_csv(data: &[u8], url: Option<&str>) {
    if !Hachimi::instance().config.load().export_circle_fan_counts {
        return;
    }

    if !is_circle_detail_response_url(url) {
        return;
    }

    let Ok(root) = rmp_serde::from_slice::<Value>(data) else {
        return;
    };

    let Some(data_obj) = root.get("data") else {
        return;
    };

    let users = data_obj
        .get("summary_user_info_array")
        .and_then(|v| v.as_array())
        .or_else(|| data_obj.get("circle_user_array").and_then(|v| v.as_array()));

    let Some(users) = users else {
        return;
    };

    let mut todays_rows: Vec<(String, String, String)> = Vec::new();
    for item in users {
        let Some(viewer_id) = item.get("viewer_id").and_then(|v| v.as_i64()) else {
            continue;
        };
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("-").to_string();
        let fan = item.get("fan").and_then(|v| v.as_i64()).unwrap_or(0);
        todays_rows.push((viewer_id.to_string(), name, fan.to_string()));
    }

    if todays_rows.is_empty() {
        return;
    }

    let now = Local::now();
    let month_name = now.format("%Y-%m").to_string();
    let day_col = now.format("%m-%d").to_string();

    let hachimi = Hachimi::instance();
    let out_dir = hachimi.get_data_path("circle");
    if let Err(e) = fs::create_dir_all(&out_dir) {
        warn!("Failed to create circle dir {}: {}", out_dir.display(), e);
        return;
    }

    let csv_path = out_dir.join(format!("{}.csv", month_name));

    let mut table: Vec<Vec<String>> = Vec::new();
    if csv_path.exists() {
        match csv::ReaderBuilder::new().has_headers(false).from_path(&csv_path) {
            Ok(mut rdr) => {
                for rec in rdr.records() {
                    if let Ok(r) = rec {
                        table.push(r.iter().map(|s| s.to_string()).collect());
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read csv {}: {}", csv_path.display(), e);
                return;
            }
        }
    }

    if table.is_empty() {
        table.push(vec!["viewer_id".to_string(), "name".to_string()]);
    }

    let mut day_idx = table[0].iter().position(|h| h == &day_col);
    if day_idx.is_none() {
        table[0].push(day_col.clone());
        day_idx = Some(table[0].len() - 1);
        let target_len = table[0].len();
        for row in table.iter_mut().skip(1) {
            while row.len() < target_len {
                row.push(String::new());
            }
        }
    }
    let day_idx = day_idx.unwrap_or(2);
    let target_len = table[0].len();

    for row in table.iter_mut().skip(1) {
        while row.len() < target_len {
            row.push(String::new());
        }
    }

    for (viewer_id, name, fan) in todays_rows {
        let existing_idx = table.iter().enumerate().skip(1)
            .find_map(|(idx, row)| row.get(0).filter(|id| *id == &viewer_id).map(|_| idx));

        if let Some(idx) = existing_idx {
            if let Some(row) = table.get_mut(idx) {
                row[1] = name;
                row[day_idx] = fan;
            }
        } else {
            let mut row = vec![String::new(); target_len];
            row[0] = viewer_id;
            row[1] = name;
            row[day_idx] = fan;
            table.push(row);
        }
    }

    match fs::File::create(&csv_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&[0xEF, 0xBB, 0xBF]) {
                warn!("Failed to write BOM to csv {}: {}", csv_path.display(), e);
                return;
            }

            let mut wtr = csv::WriterBuilder::new().has_headers(false).from_writer(file);
            for row in table {
                if let Err(e) = wtr.write_record(row) {
                    warn!("Failed to write csv row {}: {}", csv_path.display(), e);
                    return;
                }
            }
            if let Err(e) = wtr.flush() {
                warn!("Failed to flush csv {}: {}", csv_path.display(), e);
            }
        }
        Err(e) => {
            warn!("Failed to open csv for write {}: {}", csv_path.display(), e);
        }
    }
}

fn is_target_race_response_url(url: Option<&str>) -> bool {
    url.map(|url| RACE_URL_KEYWORDS.iter().any(|keyword| url.contains(keyword)))
        .unwrap_or(false)
}

fn is_circle_detail_response_url(url: Option<&str>) -> bool {
    url.map(|url| url.contains("/umamusume/circle/detail")).unwrap_or(false)
}

fn current_url_suffix(url: Option<&str>) -> String {
    url.and_then(|url| {
            let trimmed = url.trim_end_matches('/');
            if trimmed.is_empty() {
                None
            } else {
                trimmed.rsplit('/').next().map(|s| s.to_string())
            }
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn load_all_chara_ids_from_db_path(db_path: &str) -> Vec<i32> {
    let mut ids = Vec::new();

    let conn = Connection::new();
    if !Connection::Open(conn, db_path.to_il2cpp_string(), std::ptr::null_mut(), std::ptr::null_mut(), 0) {
        return ids;
    }

    let query = Connection::Query(conn, "SELECT id FROM chara_data".to_il2cpp_string());
    if !query.is_null() {
        while Query::Step(query) {
            ids.push(Query::GetInt(query, 0));
        }
        Query::Dispose(query);
    }

    Connection::CloseDB(conn);
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn load_all_dress_ids_from_db_path(db_path: &str) -> Vec<i32> {
    let mut ids = Vec::new();

    let conn = Connection::new();
    if !Connection::Open(conn, db_path.to_il2cpp_string(), std::ptr::null_mut(), std::ptr::null_mut(), 0) {
        return ids;
    }

    let query = Connection::Query(conn, "SELECT id FROM dress_data".to_il2cpp_string());
    if !query.is_null() {
        while Query::Step(query) {
            ids.push(Query::GetInt(query, 0));
        }
        Query::Dispose(query);
    }

    Connection::CloseDB(conn);
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn load_all_card_rows_from_db_path(db_path: &str) -> Vec<(i32, i32)> {
    let mut rows = Vec::new();

    let conn = Connection::new();
    if !Connection::Open(conn, db_path.to_il2cpp_string(), std::ptr::null_mut(), std::ptr::null_mut(), 0) {
        return rows;
    }

    let query = Connection::Query(conn, "SELECT id, default_rarity FROM card_data WHERE id <= 999999".to_il2cpp_string());
    if !query.is_null() {
        while Query::Step(query) {
            rows.push((Query::GetInt(query, 0), Query::GetInt(query, 1)));
        }
        Query::Dispose(query);
    }

    Connection::CloseDB(conn);
    rows.sort_unstable_by_key(|(id, _)| *id);
    rows.dedup_by_key(|(id, _)| *id);
    rows
}

fn build_masterdb_candidates() -> Vec<String> {
    let mut out = Vec::new();
    let game = &Hachimi::instance().game;

    let primary = get_masterdb_path();
    out.push(primary.clone());
    out.push(primary.replace("/master/master.mdb", "/master/master_orig.mdb"));

    out.push(format!("{}/master/master.mdb", game.data_dir.to_string_lossy().replace('\\', "/")));
    out.push(format!("{}/master/master_orig.mdb", game.data_dir.to_string_lossy().replace('\\', "/")));

    #[cfg(target_os = "android")]
    {
        let pkg = &game.package_name;
        let android_candidates = [
            format!("/data/user/0/{}/files/master/master.mdb", pkg),
            format!("/data/user/0/{}/files/master/master_orig.mdb", pkg),
        ];

        for p in android_candidates {
            out.push(p);
        }
    }

    if let Ok(user_profile) = env::var("USERPROFILE") {
        let low = format!("{}/AppData/LocalLow/Cygames/umamusume/master", user_profile.replace('\\', "/"));
        out.push(format!("{}/master.mdb", low));
        out.push(format!("{}/master_orig.mdb", low));
    }

    // Keep insertion order so primary game path is preferred over fallbacks.
    let mut deduped = Vec::new();
    for p in out {
        if !deduped.contains(&p) {
            deduped.push(p);
        }
    }
    deduped
}

fn build_masterdb_write_candidates() -> Vec<String> {
    build_masterdb_candidates()
        .into_iter()
        .filter(|p| p.ends_with("/master.mdb"))
        .collect()
}

fn ensure_master_orig(master_path: &str) {
    if !master_path.ends_with("/master.mdb") {
        return;
    }

    let orig_path = master_path.replace("/master.mdb", "/master_orig.mdb");
    if !Path::new(master_path).exists() || Path::new(&orig_path).exists() {
        return;
    }

    if let Some(parent) = Path::new(&orig_path).parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            warn!("unlock_live_chara: failed to create master backup dir '{}': {}", parent.to_string_lossy(), e);
            return;
        }
    }

    match fs::copy(master_path, &orig_path) {
        Ok(_) => info!("unlock_live_chara: created backup '{}'", orig_path),
        Err(e) => warn!("unlock_live_chara: failed to create backup '{}' from '{}': {}", orig_path, master_path, e),
    }
}

fn run_sql(conn: *mut Il2CppObject, sql: String) -> Option<i32> {
    let query = Connection::Query(conn, sql.to_il2cpp_string());
    if query.is_null() {
        return None;
    }

    // Execute at least one step so UPDATE/INSERT statements are actually applied.
    let _ = Query::Step(query);
    Query::Dispose(query);

    let changes_query = Connection::Query(conn, "SELECT changes()".to_il2cpp_string());
    if changes_query.is_null() {
        return Some(0);
    }

    let mut changes = 0;
    if Query::Step(changes_query) {
        changes = Query::GetInt(changes_query, 0);
    }
    Query::Dispose(changes_query);
    Some(changes)
}

fn query_count(conn: *mut Il2CppObject, sql: &str) -> Option<i32> {
    let query = Connection::Query(conn, sql.to_il2cpp_string());
    if query.is_null() {
        return None;
    }

    let mut out = None;
    if Query::Step(query) {
        out = Some(Query::GetInt(query, 0));
    }
    Query::Dispose(query);
    out
}

/// Synthesizes `card_data`/`card_rarity_data` rows (via the given rusqlite transaction) for dress
/// ids that exist as 3D body model assets in the meta db but have no card entry yet, i.e. costumes
/// that were never "released" as a selectable card by the server. Without a matching card_data row
/// these dresses won't show up in selection screens (e.g. live theater costume picker) even though
/// dress_data has an entry for them. Returns the number of dress ids patched this way.
fn insert_missing_dress_cards_rusqlite(tx: &rusqlite::Transaction, is_kor: bool) -> i32 {
    let mut existing_card_ids: HashSet<i32> = HashSet::new();
    if let Ok(mut stmt) = tx.prepare("SELECT id FROM card_data") {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, i32>(0)) {
            existing_card_ids.extend(rows.flatten());
        }
    }

    let mut inserted = 0;
    for dress_id in find_meta_dress_ids() {
        if existing_card_ids.contains(&dress_id) {
            continue;
        }

        let chara_id = dress_id / 100;
        let card_sql = format!(
            "INSERT INTO card_data VALUES({0},{1},3, 0, 100101, 0, 20, 0, 0, 10, 100101, 1, 100101, 3{2})",
            dress_id, chara_id, if is_kor { ", 1483196400" } else { "" }
        );

        if tx.execute(&card_sql, []).is_err() {
            continue;
        }

        let rarity_sql = format!(
            "INSERT INTO card_rarity_data VALUES({0}03, {0}, 3, {0}, 10010103, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 5, 7, 7, 1, 7, 7, 5, 7, 1, 101,{0})",
            dress_id
        );
        let _ = tx.execute(&rarity_sql, []);

        existing_card_ids.insert(dress_id);
        inserted += 1;
    }

    if inserted > 0 {
        info!("unlock_live_chara: synthesized {} card_data row(s) for unreleased dresses", inserted);
    }

    inserted
}

/// Same as [`insert_missing_dress_cards_rusqlite`] but for the LibNative connection fallback path.
fn insert_missing_dress_cards_libnative(conn: *mut Il2CppObject, is_kor: bool) -> i32 {
    let mut existing_card_ids: HashSet<i32> = HashSet::new();
    let query = Connection::Query(conn, "SELECT id FROM card_data".to_il2cpp_string());
    if !query.is_null() {
        while Query::Step(query) {
            existing_card_ids.insert(Query::GetInt(query, 0));
        }
        Query::Dispose(query);
    }

    let mut inserted = 0;
    for dress_id in find_meta_dress_ids() {
        if existing_card_ids.contains(&dress_id) {
            continue;
        }

        let chara_id = dress_id / 100;
        let card_sql = format!(
            "INSERT INTO card_data VALUES({0},{1},3, 0, 100101, 0, 20, 0, 0, 10, 100101, 1, 100101, 3{2})",
            dress_id, chara_id, if is_kor { ", 1483196400" } else { "" }
        );

        if run_sql(conn, card_sql).is_none() {
            continue;
        }

        let rarity_sql = format!(
            "INSERT INTO card_rarity_data VALUES({0}03, {0}, 3, {0}, 10010103, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 5, 7, 7, 1, 7, 7, 5, 7, 1, 101,{0})",
            dress_id
        );
        let _ = run_sql(conn, rarity_sql);

        existing_card_ids.insert(dress_id);
        inserted += 1;
    }

    if inserted > 0 {
        info!("unlock_live_chara: synthesized {} card_data row(s) for unreleased dresses (fallback)", inserted);
    }

    inserted
}

/// Some dresses can have a legitimate `card_data` row pushed by the server ahead of their actual
/// release, while their `card_rarity_data` row(s) (holding rarity/stat info the game needs to
/// render the costume) are still missing or claimed by another dress. `card_rarity_data`'s
/// `card_id` is really a per-character *slot* number: an earlier-released dress can grab the slot
/// that numerically matches a later dress's own id (e.g. dress 102226 released first and grabbed
/// slot "02" under character 1022, whose virtual id 102202 collides with a real, later dress
/// 102202's own id). Column 3 holds the actual dress a row renders, so a dress is only "covered"
/// once some row's column 3 actually equals its id.
///
/// When the natural slot is taken, we allocate the next free slot (e.g. 102203) and, since
/// `card_rarity_data.card_id` must reference a real `card_data.id`, also synthesize a matching
/// `card_data` row for that new slot id (mirroring [`insert_missing_dress_cards_rusqlite`]'s
/// template) so the two tables stay consistent.
fn ensure_dress_card_rarity_rows_rusqlite(tx: &rusqlite::Transaction, is_kor: bool) -> i32 {
    let mut card_ids: HashSet<i32> = HashSet::new();
    if let Ok(mut stmt) = tx.prepare("SELECT id FROM card_data") {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, i32>(0)) {
            card_ids.extend(rows.flatten());
        }
    }

    // Read positionally (column 0 = id, column 1 = card_id/slot, column 3 = the dress this row
    // actually renders) since we don't know the real column names.
    let mut existing_ids: HashSet<i32> = HashSet::new();
    let mut covering_card_id: std::collections::HashMap<i32, i32> = std::collections::HashMap::new();
    if let Ok(mut stmt) = tx.prepare("SELECT * FROM card_rarity_data") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, i32>(0)?, row.get::<_, i32>(1)?, row.get::<_, i32>(3)?))
        }) {
            for (id, card_id, dress_ref) in rows.flatten() {
                existing_ids.insert(id);
                covering_card_id.entry(dress_ref).or_insert(card_id);
            }
        }
    }

    let mut dress_ids: Vec<i32> = Vec::new();
    if let Ok(mut stmt) = tx.prepare("SELECT id FROM dress_data") {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, i32>(0)) {
            dress_ids.extend(rows.flatten());
        }
    }

    let mut inserted = 0;
    for dress_id in dress_ids {
        if !card_ids.contains(&dress_id) {
            continue;
        }

        // Some row (under whatever slot id) already renders this exact dress. Normally nothing
        // more to do, but a previous buggy run could have inserted the card_rarity_data row while
        // failing to insert its matching card_data row - self-heal that here instead of skipping.
        if let Some(&existing_card_id) = covering_card_id.get(&dress_id) {
            if card_ids.contains(&existing_card_id) {
                continue;
            }

            let chara_id = existing_card_id / 100;
            let card_sql = format!(
                "INSERT INTO card_data VALUES({0},{1},3, 0, 100101, 0, 20, 0, 0, 10, 100101, 1, 100101, 3{2})",
                existing_card_id, chara_id, if is_kor { ", 1483196400" } else { "" }
            );
            match tx.execute(&card_sql, []) {
                Ok(_) => {
                    card_ids.insert(existing_card_id);
                    inserted += 1;
                    info!("unlock_live_chara: repaired missing card_data id={} for already-covered dress={}", existing_card_id, dress_id);
                }
                Err(e) => {
                    warn!("unlock_live_chara: failed to repair card_data id={} for dress={}: {}", existing_card_id, dress_id, e);
                }
            }
            continue;
        }

        // Walk forward within this character's id block (chara_id*100 .. chara_id*100+99) to find
        // a slot that isn't already occupied by an unrelated dress's rarity rows or card.
        let group_base = (dress_id / 100) * 100;
        let mut virtual_id = dress_id;
        while existing_ids.iter().any(|id| id / 100 == virtual_id) || card_ids.contains(&virtual_id) {
            virtual_id += 1;
            if virtual_id >= group_base + 100 {
                // No free slot found; fall back to the natural id anyway (best effort).
                virtual_id = dress_id;
                break;
            }
        }

        // If we had to move off the dress's own id, card_rarity_data.card_id will reference a
        // slot id that has no matching card_data row yet - synthesize one so the FK is valid.
        if virtual_id != dress_id {
            let chara_id = virtual_id / 100;
            let card_sql = format!(
                "INSERT INTO card_data VALUES({0},{1},3, 0, 100101, 0, 20, 0, 0, 10, 100101, 1, 100101, 3{2})",
                virtual_id, chara_id, if is_kor { ", 1483196400" } else { "" }
            );
            match tx.execute(&card_sql, []) {
                Ok(_) => {
                    card_ids.insert(virtual_id);
                }
                Err(e) => {
                    warn!("unlock_live_chara: failed to insert placeholder card_data id={} for dress={}: {}", virtual_id, dress_id, e);
                    continue;
                }
            }
        }

        let rarity_sql = format!(
            "INSERT INTO card_rarity_data VALUES({virt}03, {virt}, 3, {dress}, 10010103, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 5, 7, 7, 1, 7, 7, 5, 7, 1, 101,{dress})",
            virt = virtual_id,
            dress = dress_id
        );
        match tx.execute(&rarity_sql, []) {
            Ok(_) => {
                existing_ids.insert(virtual_id * 100 + 3);
                inserted += 1;
            }
            Err(e) => {
                warn!("unlock_live_chara: failed to insert card_rarity_data virt={} for dress={}: {}", virtual_id, dress_id, e);
            }
        }
    }

    if inserted > 0 {
        info!("unlock_live_chara: synthesized {} card_rarity_data row(s) for existing dress cards missing rarity data", inserted);
    }

    inserted
}

/// Same as [`ensure_dress_card_rarity_rows_rusqlite`] but for the LibNative connection fallback path.
fn ensure_dress_card_rarity_rows_libnative(conn: *mut Il2CppObject, is_kor: bool) -> i32 {
    let mut card_ids: HashSet<i32> = HashSet::new();
    let query = Connection::Query(conn, "SELECT id FROM card_data".to_il2cpp_string());
    if !query.is_null() {
        while Query::Step(query) {
            card_ids.insert(Query::GetInt(query, 0));
        }
        Query::Dispose(query);
    }

    let mut existing_ids: HashSet<i32> = HashSet::new();
    let mut covering_card_id: std::collections::HashMap<i32, i32> = std::collections::HashMap::new();
    let query2 = Connection::Query(conn, "SELECT * FROM card_rarity_data".to_il2cpp_string());
    if !query2.is_null() {
        while Query::Step(query2) {
            let id = Query::GetInt(query2, 0);
            let card_id = Query::GetInt(query2, 1);
            let dress_ref = Query::GetInt(query2, 3);
            existing_ids.insert(id);
            covering_card_id.entry(dress_ref).or_insert(card_id);
        }
        Query::Dispose(query2);
    }

    let mut dress_ids: Vec<i32> = Vec::new();
    let query3 = Connection::Query(conn, "SELECT id FROM dress_data".to_il2cpp_string());
    if !query3.is_null() {
        while Query::Step(query3) {
            dress_ids.push(Query::GetInt(query3, 0));
        }
        Query::Dispose(query3);
    }

    let mut inserted = 0;
    for dress_id in dress_ids {
        if !card_ids.contains(&dress_id) {
            continue;
        }

        if let Some(&existing_card_id) = covering_card_id.get(&dress_id) {
            if card_ids.contains(&existing_card_id) {
                continue;
            }

            let chara_id = existing_card_id / 100;
            let card_sql = format!(
                "INSERT INTO card_data VALUES({0},{1},3, 0, 100101, 0, 20, 0, 0, 10, 100101, 1, 100101, 3{2})",
                existing_card_id, chara_id, if is_kor { ", 1483196400" } else { "" }
            );
            match run_sql(conn, card_sql) {
                Some(changes) if changes > 0 => {
                    card_ids.insert(existing_card_id);
                    inserted += 1;
                    info!("unlock_live_chara: repaired missing card_data id={} for already-covered dress={} (fallback)", existing_card_id, dress_id);
                }
                _ => {
                    warn!("unlock_live_chara: failed to repair card_data id={} for dress={} (fallback)", existing_card_id, dress_id);
                }
            }
            continue;
        }

        let group_base = (dress_id / 100) * 100;
        let mut virtual_id = dress_id;
        while existing_ids.iter().any(|id| id / 100 == virtual_id) || card_ids.contains(&virtual_id) {
            virtual_id += 1;
            if virtual_id >= group_base + 100 {
                virtual_id = dress_id;
                break;
            }
        }

        if virtual_id != dress_id {
            let chara_id = virtual_id / 100;
            let card_sql = format!(
                "INSERT INTO card_data VALUES({0},{1},3, 0, 100101, 0, 20, 0, 0, 10, 100101, 1, 100101, 3{2})",
                virtual_id, chara_id, if is_kor { ", 1483196400" } else { "" }
            );
            match run_sql(conn, card_sql) {
                Some(changes) if changes > 0 => {
                    card_ids.insert(virtual_id);
                }
                _ => {
                    warn!("unlock_live_chara: failed to insert placeholder card_data id={} for dress={} (fallback)", virtual_id, dress_id);
                    continue;
                }
            }
        }

        let rarity_sql = format!(
            "INSERT INTO card_rarity_data VALUES({virt}03, {virt}, 3, {dress}, 10010103, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 5, 7, 7, 1, 7, 7, 5, 7, 1, 101,{dress})",
            virt = virtual_id,
            dress = dress_id
        );
        match run_sql(conn, rarity_sql) {
            Some(changes) if changes > 0 => {
                existing_ids.insert(virtual_id * 100 + 3);
                inserted += 1;
            }
            _ => {
                warn!("unlock_live_chara: failed to insert card_rarity_data virt={} for dress={} (fallback)", virtual_id, dress_id);
            }
        }
    }

    if inserted > 0 {
        info!("unlock_live_chara: synthesized {} card_rarity_data row(s) for existing dress cards missing rarity data (fallback)", inserted);
    }

    inserted
}

fn patch_unlock_db_rusqlite(db_path: &str, now: i64, start_ts: i64, is_kor: bool) -> Option<(i32, i32, i32, i32, i32, i32, i32)> {
    let conn = RusqliteConnection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE,
    ).ok()?;

    let _ = conn.busy_timeout(Duration::from_secs(2));

    let pre_dress_unlockable: i32 = conn.query_row(
        "SELECT COUNT(1) FROM dress_data WHERE use_live != 1 OR use_live_theater != 1",
        [],
        |row| row.get(0),
    ).unwrap_or(-1);
    let pre_dress_future: i32 = conn.query_row(
        &format!("SELECT COUNT(1) FROM dress_data WHERE start_time > {}", now),
        [],
        |row| row.get(0),
    ).unwrap_or(-1);
    let pre_live_future: i32 = conn.query_row(
        &format!("SELECT COUNT(1) FROM live_data WHERE has_live = 1 AND start_date > {}", now),
        [],
        |row| row.get(0),
    ).unwrap_or(-1);
    let pre_chara_future: i32 = conn.query_row(
        &format!("SELECT COUNT(1) FROM chara_data WHERE start_date > {}", now),
        [],
        |row| row.get(0),
    ).unwrap_or(-1);
    let pre_shape_9001: i32 = conn.query_row(
        "SELECT shape FROM chara_data WHERE id = 9001",
        [],
        |row| row.get(0),
    ).unwrap_or(-1);

    let tx = conn.unchecked_transaction().ok()?;

    let mut total_changes = 0i32;
    let statements = [
        "UPDATE dress_data SET use_live = 1, use_live_theater = 1".to_string(),
        format!("UPDATE dress_data SET start_time = {} WHERE start_time > {}", start_ts, now),
        "UPDATE dress_data SET general_purpose = 1, costume_type = 1 WHERE id >= 200000 AND id <= 299999 AND body_type = 100".to_string(),
        "UPDATE dress_data SET body_type = 230 WHERE id > 299999 AND body_type = 100".to_string(),
        "UPDATE dress_data SET body_type = 230 WHERE id LIKE '1___60'".to_string(),
        format!("UPDATE live_data SET start_date = {} WHERE has_live = 1 AND start_date > {}", start_ts, now),
        format!("UPDATE chara_data SET start_date = {} WHERE start_date > {}", start_ts, now),
        "UPDATE chara_data SET shape = 1 WHERE id = 9001".to_string(),
    ];

    for sql in statements {
        match tx.execute(&sql, []) {
            Ok(changes) => total_changes += changes as i32,
            Err(e) => {
                warn!("unlock_live_chara: rusqlite SQL failed on '{}': {} ({})", db_path, sql, e);
                return None;
            }
        }
    }

    let cards_inserted = insert_missing_dress_cards_rusqlite(&tx, is_kor)
        + ensure_dress_card_rarity_rows_rusqlite(&tx, is_kor);

    if tx.commit().is_err() {
        return None;
    }

    Some((
        total_changes,
        pre_dress_unlockable,
        pre_dress_future,
        pre_live_future,
        pre_chara_future,
        pre_shape_9001,
        cards_inserted,
    ))
}

fn patch_unlock_db_once() {
    if UNLOCK_DB_PATCHED.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }

    let now = chrono::Utc::now().timestamp();
    let start_ts = 1_483_196_400i64;
    let is_kor = Hachimi::instance().game.region == Region::Korea;
    let mut patched_paths: Vec<String> = Vec::new();

    for candidate in build_masterdb_write_candidates() {
        ensure_master_orig(&candidate);

        if !Path::new(&candidate).exists() {
            continue;
        }

        if let Some((
            total_changes,
            pre_dress_unlockable,
            pre_dress_future,
            pre_live_future,
            pre_chara_future,
            pre_shape_9001,
            cards_inserted,
        )) = patch_unlock_db_rusqlite(&candidate, now, start_ts, is_kor) {
            info!(
                "unlock_live_chara: patch stats db='{}' open_mode=rusqlite total_changes={} cards_inserted={} pre[dress_unlockable={},dress_future={},live_future={},chara_future={},shape9001={}]",
                candidate,
                total_changes,
                cards_inserted,
                pre_dress_unlockable,
                pre_dress_future,
                pre_live_future,
                pre_chara_future,
                pre_shape_9001
            );
            patched_paths.push(candidate);
            continue;
        }
        warn!("unlock_live_chara: rusqlite patch failed, fallback to LibNative connection for '{}'", candidate);

        let conn = Connection::new();
        let opened_default = Connection::Open(conn, candidate.to_il2cpp_string(), std::ptr::null_mut(), std::ptr::null_mut(), 0);
        let opened_alt = !opened_default
            && Connection::Open(conn, candidate.to_il2cpp_string(), std::ptr::null_mut(), std::ptr::null_mut(), 1);
        let opened = opened_default || opened_alt;
        if !opened {
            continue;
        }

        let pre_dress_unlockable = query_count(conn, "SELECT COUNT(1) FROM dress_data WHERE use_live != 1 OR use_live_theater != 1").unwrap_or(-1);
        let pre_dress_future = query_count(conn, &format!("SELECT COUNT(1) FROM dress_data WHERE start_time > {}", now)).unwrap_or(-1);
        let pre_live_future = query_count(conn, &format!("SELECT COUNT(1) FROM live_data WHERE has_live = 1 AND start_date > {}", now)).unwrap_or(-1);
        let pre_chara_future = query_count(conn, &format!("SELECT COUNT(1) FROM chara_data WHERE start_date > {}", now)).unwrap_or(-1);
        let pre_shape_9001 = query_count(conn, "SELECT shape FROM chara_data WHERE id = 9001").unwrap_or(-1);

        let mut total_changes = 0;
        let mut ok = true;
        for sql in [
            "UPDATE dress_data SET use_live = 1, use_live_theater = 1".to_string(),
            format!("UPDATE dress_data SET start_time = {} WHERE start_time > {}", start_ts, now),
            "UPDATE dress_data SET general_purpose = 1, costume_type = 1 WHERE id >= 200000 AND id <= 299999 AND body_type = 100".to_string(),
            "UPDATE dress_data SET body_type = 230 WHERE id > 299999 AND body_type = 100".to_string(),
            "UPDATE dress_data SET body_type = 230 WHERE id LIKE '1___60'".to_string(),
            format!("UPDATE live_data SET start_date = {} WHERE has_live = 1 AND start_date > {}", start_ts, now),
            format!("UPDATE chara_data SET start_date = {} WHERE start_date > {}", start_ts, now),
            "UPDATE chara_data SET shape = 1 WHERE id = 9001".to_string(),
        ] {
            match run_sql(conn, sql.clone()) {
                Some(changes) => {
                    total_changes += changes;
                }
                None => {
                    warn!("unlock_live_chara: SQL failed on '{}': {}", candidate, sql);
                    ok = false;
                    break;
                }
            }
        }

        let cards_inserted = if ok {
            insert_missing_dress_cards_libnative(conn, is_kor) + ensure_dress_card_rarity_rows_libnative(conn, is_kor)
        } else {
            0
        };

        Connection::CloseDB(conn);

        if ok {
            info!(
                "unlock_live_chara: patch stats db='{}' open_mode={} total_changes={} cards_inserted={} pre[dress_unlockable={},dress_future={},live_future={},chara_future={},shape9001={}]",
                candidate,
                if opened_default { 0 } else { 1 },
                total_changes,
                cards_inserted,
                pre_dress_unlockable,
                pre_dress_future,
                pre_live_future,
                pre_chara_future,
                pre_shape_9001
            );
            patched_paths.push(candidate);
        }
    }

    if !patched_paths.is_empty() {
        if let Ok(mut guard) = UNLOCK_CHARA_IDS.write() {
            *guard = None;
        }
        if let Ok(mut guard) = UNLOCK_DRESS_IDS.write() {
            *guard = None;
        }
        if let Ok(mut guard) = UNLOCK_CARD_ROWS.write() {
            *guard = None;
        }

        UNLOCK_DB_PATCHED.store(true, std::sync::atomic::Ordering::Release);
        info!("unlock_live_chara: initialized unlock flags in {} DB file(s)", patched_paths.len());
        for p in patched_paths {
            info!("unlock_live_chara: patched DB '{}'", p);
        }
    }
}

fn get_unlock_chara_ids() -> Vec<i32> {
    if let Ok(guard) = UNLOCK_CHARA_IDS.read() {
        if let Some(ids) = guard.as_ref() {
            return ids.clone();
        }
    }

    let cached_ids: Vec<i32> = {
        let data = Hachimi::instance().chara_data.load();
        if data.chara_ids.is_empty() {
            Vec::new()
        }
        else {
            let mut v: Vec<i32> = data.chara_ids.iter().copied().collect();
            v.sort_unstable();
            v
        }
    };

    if !cached_ids.is_empty() {
        if let Ok(mut guard) = UNLOCK_CHARA_IDS.write() {
            *guard = Some(cached_ids.clone());
        }
        return cached_ids;
    }

    for candidate in build_masterdb_candidates() {
        let exists = Path::new(&candidate).exists();

        if !exists {
            continue;
        }

        let ids = load_all_chara_ids_from_db_path(&candidate);
        if !ids.is_empty() {
            let mut merged_ids = ids;
            let dress_ids = load_all_dress_ids_from_db_path(&candidate);
            let before = merged_ids.len();
            for dress_id in dress_ids {
                let derived = dress_id / 100;
                if (1000..=9999).contains(&derived) {
                    merged_ids.push(derived);
                }
            }
            merged_ids.sort_unstable();
            merged_ids.dedup();

            info!(
                "unlock_live_chara: using DB '{}' chara_ids={} (base={}, derived={})",
                candidate,
                merged_ids.len(),
                before,
                merged_ids.len().saturating_sub(before)
            );
            if let Ok(mut guard) = UNLOCK_CHARA_IDS.write() {
                *guard = Some(merged_ids.clone());
            }
            return merged_ids;
        }
    }

    Vec::new()
}

fn get_unlock_dress_ids() -> Vec<i32> {
    if let Ok(guard) = UNLOCK_DRESS_IDS.read() {
        if let Some(ids) = guard.as_ref() {
            return ids.clone();
        }
    }

    for candidate in build_masterdb_candidates() {
        if !Path::new(&candidate).exists() {
            continue;
        }

        let ids = load_all_dress_ids_from_db_path(&candidate);
        if !ids.is_empty() {
            info!("unlock_live_chara: using dress DB '{}' ids={}", candidate, ids.len());
            if let Ok(mut guard) = UNLOCK_DRESS_IDS.write() {
                *guard = Some(ids.clone());
            }
            return ids;
        }
    }

    Vec::new()
}

fn get_unlock_card_rows() -> Vec<(i32, i32)> {
    if let Ok(guard) = UNLOCK_CARD_ROWS.read() {
        if let Some(rows) = guard.as_ref() {
            return rows.clone();
        }
    }

    for candidate in build_masterdb_candidates() {
        if !Path::new(&candidate).exists() {
            continue;
        }

        let mut rows = load_all_card_rows_from_db_path(&candidate);
        if !rows.is_empty() {
            let base_len = rows.len();
            let dress_ids = load_all_dress_ids_from_db_path(&candidate);
            for dress_id in dress_ids {
                if (100000..=999999).contains(&dress_id) {
                    rows.push((dress_id, 3));
                }
            }
            rows.sort_unstable_by_key(|(id, _)| *id);
            rows.dedup_by_key(|(id, _)| *id);

            info!(
                "unlock_live_chara: using card DB '{}' rows={} (base={}, derived={})",
                candidate,
                rows.len(),
                base_len,
                rows.len().saturating_sub(base_len)
            );
            if let Ok(mut guard) = UNLOCK_CARD_ROWS.write() {
                *guard = Some(rows.clone());
            }
            return rows;
        }
    }

    Vec::new()
}

fn sanitize_filename_component(input: &str) -> String {
    const ILLEGAL: &str = "\\/:*?\"<>|";
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_control() || ILLEGAL.contains(c) {
            out.push('-');
        } else {
            out.push(c);
        }
    }

    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

fn patch_unlock_live_chara_response(data: &[u8]) -> Option<Vec<u8>> {
    if !Hachimi::instance().config.load().unlock_live_chara {
        return None;
    }

    patch_unlock_db_once();

    let chara_ids = get_unlock_chara_ids();
    if chara_ids.is_empty() {
        return None;
    }

    let mut root = rmp_serde::from_slice::<Value>(data).ok()?;
    let data_obj = root.get_mut("data").and_then(|v| v.as_object_mut())?;

    let mut changed = false;

    for key in ["chara_list", "user_chara_list", "user_chara_array"] {
        let Some(chara_list_value) = data_obj.get_mut(key) else {
            continue;
        };
        if let Some(chara_list) = chara_list_value.as_array() {
            let mut chara_map = std::collections::BTreeMap::new();
            for chara in chara_list {
                if let Some(chara_obj) = chara.as_object() {
                    if let Some(chara_id) = chara_obj.get("chara_id").and_then(|v| v.as_i64()) {
                        chara_map.insert(chara_id as i32, chara.clone());
                    }
                }
            }

            let mut patched = Vec::with_capacity(chara_ids.len());
            for chara_id in &chara_ids {
                let chara_id = *chara_id;
                if let Some(existing) = chara_map.get(&chara_id) {
                    patched.push(existing.clone());
                }
                else {
                    patched.push(json!({
                        "chara_id": chara_id,
                        "training_num": 0,
                        "love_point": 0,
                        "fan": 1,
                        "max_grade": 0,
                        "dress_id": 2,
                        "mini_dress_id": 2,
                        "love_point_pool": 0
                    }));
                }
            }

            *chara_list_value = Value::Array(patched);
            changed = true;
            break;
        }
    }

    for key in ["chara_profile_array", "user_chara_profile_array"] {
        let Some(profile_value) = data_obj.get_mut(key) else {
            continue;
        };
        if let Some(profile_array) = profile_value.as_array() {
            let mut profile_map = std::collections::BTreeMap::new();
            for profile in profile_array {
                if let Some(profile_obj) = profile.as_object() {
                    if let Some(chara_id) = profile_obj.get("chara_id").and_then(|v| v.as_i64()) {
                        profile_map.insert(chara_id as i32, profile.clone());
                    }
                }
            }

            let mut patched = Vec::with_capacity(chara_ids.len());
            for chara_id in &chara_ids {
                let chara_id = *chara_id;
                if let Some(existing) = profile_map.get(&chara_id) {
                    patched.push(existing.clone());
                }
                else {
                    patched.push(json!({
                        "chara_id": chara_id,
                        "data_id": 1,
                        "new_flag": 0
                    }));
                }
            }

            *profile_value = Value::Array(patched);
            changed = true;
            break;
        }
    }

    let dress_ids = get_unlock_dress_ids();
    if !dress_ids.is_empty() {
        for key in ["cloth_list", "user_cloth_list", "user_dress_list"] {
            let Some(cloth_list_value) = data_obj.get_mut(key) else {
                continue;
            };
            if cloth_list_value.as_array().is_some() {
                let mut patched = Vec::with_capacity(dress_ids.len());
                for dress_id in &dress_ids {
                    patched.push(json!({
                        "cloth_id": *dress_id
                    }));
                }

                *cloth_list_value = Value::Array(patched);
                changed = true;
                break;
            }
        }
    }

    let card_rows = get_unlock_card_rows();
    if !card_rows.is_empty() {
        for key in ["release_card_array", "user_release_card_array"] {
            let Some(release_cards_value) = data_obj.get_mut(key) else {
                continue;
            };
            if release_cards_value.as_array().is_some() {
                let mut patched = Vec::with_capacity(card_rows.len());
                for (card_id, _) in &card_rows {
                    patched.push(json!(*card_id));
                }

                *release_cards_value = Value::Array(patched);
                changed = true;
                break;
            }
        }

        for key in ["card_list", "user_card_list"] {
            let Some(card_list_value) = data_obj.get_mut(key) else {
                continue;
            };
            if let Some(card_list) = card_list_value.as_array() {
                let mut card_map = std::collections::BTreeMap::new();
                for card in card_list {
                    if let Some(card_obj) = card.as_object() {
                        if let Some(card_id) = card_obj.get("card_id").and_then(|v| v.as_i64()) {
                            card_map.insert(card_id as i32, card.clone());
                        }
                    }
                }

                let mut patched = Vec::with_capacity(card_rows.len());
                for (card_id, default_rarity) in &card_rows {
                    if let Some(existing) = card_map.get(card_id) {
                        let mut obj = existing.as_object().cloned().unwrap_or_default();
                        let rarity = obj.get("rarity").and_then(|v| v.as_i64()).unwrap_or(*default_rarity as i64);
                        if rarity < 3 {
                            obj.insert("rarity".to_string(), json!(3));
                        }
                        patched.push(Value::Object(obj));
                    }
                    else {
                        patched.push(json!({
                            "null": 1,
                            "card_id": *card_id,
                            "rarity": *default_rarity,
                            "talent_level": 1,
                            "create_time": "2022-07-01 12:00:00",
                            "skill_data_array": []
                        }));
                    }
                }

                *card_list_value = Value::Array(patched);
                changed = true;
                break;
            }
        }
    }

    if !changed {
        return None;
    }

    rmp_serde::to_vec(&root).ok()
}

fn make_byte_array(bytes: &[u8]) -> Option<*mut Il2CppArray> {
    unsafe {
        if BYTE_CLASS.is_null() {
            return None;
        }

        let out = Array::<u8>::new(BYTE_CLASS, bytes.len());
        out.as_slice().copy_from_slice(bytes);
        Some(out.this)
    }
}

extern "C" fn CompressRequest(data: *mut Il2CppArray) -> *mut Il2CppArray {
    let body = unsafe { Array::<u8>::from(data).as_slice().to_vec() };
    let compressed = get_orig_fn!(CompressRequest, CompressRequestFn)(data);
    // Park the body until Post supplies the URL; matched by the compressed array's identity.
    queue_pending_request(compressed as usize, body);
    compressed
}
extern "C" fn DecompressResponse(data: *mut Il2CppArray) -> *mut Il2CppArray {
    let decompressed = get_orig_fn!(DecompressResponse, DecompressResponseFn)(data);
    unsafe {
        let buffer = Array::<u8>::from(decompressed);
        let data = buffer.as_slice();

        // Pop the URL queued by this response's originating request; see POST_URL_QUEUE.
        let response_url = take_next_post_url();

        save_circle_monthly_csv(data, response_url.as_deref());
        save_response_msgpack(data, response_url.as_deref());
        if let Err(e) = post_with_url(RESPONSE.as_str(), response_url.as_deref(), data) {
            warn!("notifier: failed to forward response to '{}': {}", RESPONSE.as_str(), e);
        }

        if let Some(modified) = patch_unlock_live_chara_response(data) {
            if let Some(new_array) = make_byte_array(&modified) {
                return new_array;
            }
            warn!("unlock_live_chara patch generated data but failed to allocate managed byte array");
        }
    }
    decompressed
}

pub fn init(img: *const Il2CppImage) {
    get_class_or_return!(img, "Gallop", HttpHelper);

    if let Ok(mscorlib_img) = get_assembly_image(c"mscorlib.dll") {
        if let Ok(byte_class) = get_class(mscorlib_img, c"System", c"Byte") {
            unsafe {
                BYTE_CLASS = byte_class;
            }
        }
    }

    if let Ok(cute_http_img) = get_assembly_image(c"Cute.Http.Assembly.dll") {
        if let Ok(www_request) = get_class(cute_http_img, c"Cute.Http", c"WWWRequest") {
            let POST_ADDR = get_method_addr(www_request, c"Post", 3);
            new_hook!(POST_ADDR, Post);
        }
    }

    let COMPRESSREQUEST_ADDR = get_method_addr(HttpHelper, c"CompressRequest", 1);
    let DECOMPRESSRESPONSE_ADDR = get_method_addr(HttpHelper, c"DecompressResponse", 1);

    new_hook!(COMPRESSREQUEST_ADDR, CompressRequest);
    new_hook!(DECOMPRESSRESPONSE_ADDR, DecompressResponse);
}
