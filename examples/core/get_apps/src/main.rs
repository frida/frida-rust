use frida::{Scope, DeviceType};

fn main() {
    let frida = unsafe { frida::Frida::obtain() };
    let device_manager = frida::DeviceManager::obtain(&frida);
    let device = device_manager.get_usb_device().unwrap();
    assert_eq!(device.get_type(), DeviceType::USB);
    let apps = device.enumerate_applications(None, None);

    if !apps.is_empty() {
        // query detail of the first app
        let identifier = apps[0].get_identifier();
        let single = device.enumerate_applications(Some(&[identifier]), Some(Scope::Full));
        let first = single.first().unwrap();
        let params = first.get_parameters().unwrap();

        println!("parameters of {}: ", first.get_identifier());
        for (k, v) in params {
            println!("{}: {:?}", k, v);
        }

        println!("---");

        if let Some(frontmost) = device.frontmost_application(None) {
            println!("frontmost: {} {} {:?}", frontmost.get_name(), frontmost.get_identifier(), frontmost.get_pid());
            println!("---");
        }
    }

    for a in apps {
        println!("{} {} {:?}", a.get_name(), a.get_identifier(), a.get_pid());
    }
}
