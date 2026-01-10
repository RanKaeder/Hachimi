pub mod Gallop_HttpHelper;

pub fn init() {
    get_assembly_image_or_return!(image, "umamusume.dll");

    Gallop_HttpHelper::init(image);
}
