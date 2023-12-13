use frida::DeviceType;

fn main() {
    let frida = unsafe { frida::Frida::obtain() };
    let device_manager = frida::DeviceManager::obtain(&frida);

    // get the first usb device (assuming there is one attached)
    let device = device_manager.get_device_by_type(DeviceType::USB).unwrap();
    assert_eq!(device.get_type(), DeviceType::USB);
    println!(
        "found {} with type: {}",
        device.get_name(),
        device.get_type()
    );

    // get the device id and use it to obtain a the device by the id
    let device_id = device.get_id();
    let device = device_manager.get_device_by_id(device_id).unwrap();
    assert_eq!(device.get_id(), device_id);
    println!("found {} with id: {}", device.get_name(), device.get_id());
}
