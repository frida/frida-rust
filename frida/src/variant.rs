use std::collections::HashMap;
use std::ffi::{CStr, CString};

#[derive(Clone, PartialEq, Eq)]
/// GVariant types used by Frida
pub enum Variant {
    /// String
    String(String),

    /// Boolean value
    Boolean(bool),

    /// Integer value
    Int64(i64),

    /// Map
    Map(HashMap<String, Variant>),

    /// Array of Maps
    MapList(Vec<HashMap<String, Variant>>),
}

impl Variant {
    /// Construct a GVariant from a raw pointer
    pub(crate) unsafe fn from_ptr(variant: *mut frida_sys::GVariant) -> Self {
        match variant_string(variant).as_str() {
            "s" => {
                let mut sz = 0;
                let value = CStr::from_ptr(frida_sys::g_variant_get_string(variant, &mut sz))
                    .to_string_lossy()
                    .to_string();
                Self::String(value)
            }
            "b" => {
                Self::Boolean(frida_sys::g_variant_get_boolean(variant) != frida_sys::FALSE as _)
            }
            "x" => Self::Int64(frida_sys::g_variant_get_int64(variant)),
            "a{sv}" => Self::Map(sv_array_to_map(variant)),
            "aa{sv}" => Self::MapList(asv_array_to_maplist(variant)),
            other => todo!("Unimplemented variant: {other}"),
        }
    }

    /// Get the string value of a variant, if any
    pub fn get_string(&self) -> Option<&str> {
        let Self::String(ref s) = self else {
            return None;
        };
        Some(s)
    }

    /// Get the integer value of a variant, if any
    pub fn get_int(&self) -> Option<i64> {
        let Self::Int64(i) = self else { return None };
        Some(*i)
    }

    /// Get the boolean value of a variant, if any
    pub fn get_bool(&self) -> Option<bool> {
        let Self::Boolean(b) = self else { return None };
        Some(*b)
    }

    /// Get the mapping value of a variant, if any
    pub fn get_map(&self) -> Option<&HashMap<String, Variant>> {
        let Self::Map(ref m) = self else { return None };
        Some(m)
    }

    /// Get the mapping list value of a variant, if any
    pub fn get_maplist(&self) -> Option<&[HashMap<String, Variant>]> {
        let Self::MapList(ref l) = self else {
            return None;
        };
        Some(l)
    }
}

impl std::fmt::Debug for Variant {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::String(s) => s.fmt(f),
            Self::Int64(num) => num.fmt(f),
            Self::Boolean(b) => b.fmt(f),
            Self::Map(m) => m.fmt(f),
            Self::MapList(l) => l.fmt(f),
        }
    }
}

unsafe fn variant_string(variant: *mut frida_sys::GVariant) -> String {
    CStr::from_ptr(frida_sys::g_variant_get_type_string(variant))
        .to_string_lossy()
        .to_string()
}

unsafe fn sv_array_to_map(variant: *mut frida_sys::GVariant) -> HashMap<String, Variant> {
    let mut ret = HashMap::new();

    let mut iter: frida_sys::GVariantIter = std::mem::MaybeUninit::zeroed().assume_init();
    let mut value: *mut frida_sys::GVariant = std::ptr::null_mut();
    let mut key: *const i8 = std::ptr::null_mut();

    frida_sys::g_variant_iter_init(&mut iter, variant);
    let sv = CString::new("{sv}").unwrap();
    while frida_sys::g_variant_iter_loop(&mut iter, sv.as_ptr(), &mut key, &mut value) != 0 {
        let key = CStr::from_ptr(key).to_string_lossy().to_string();
        let value = Variant::from_ptr(value);
        ret.insert(key, value);
    }
    ret
}

unsafe fn asv_array_to_maplist(variant: *mut frida_sys::GVariant) -> Vec<HashMap<String, Variant>> {
    let mut ret = Vec::new();
    let mut outer: frida_sys::GVariantIter = std::mem::MaybeUninit::zeroed().assume_init();
    let mut inner = std::ptr::null_mut();
    let mut key: *const i8 = std::ptr::null_mut();
    let mut value: *mut frida_sys::GVariant = std::ptr::null_mut();

    frida_sys::g_variant_iter_init(&mut outer, variant);
    let asv = CString::new("a{sv}").unwrap();
    let sv = CString::new("{sv}").unwrap();
    while frida_sys::g_variant_iter_loop(&mut outer, asv.as_ptr(), &mut inner) != 0 {
        let mut map = HashMap::new();
        while frida_sys::g_variant_iter_loop(inner, sv.as_ptr(), &mut key, &mut value) != 0 {
            let key = CStr::from_ptr(key).to_string_lossy().to_string();
            let value = Variant::from_ptr(value);
            map.insert(key, value);
        }
        ret.push(map)
    }

    ret
}
