//! Shell icon of an executable as PNG.

use std::mem::{size_of, zeroed};
use windows_sys::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO, BITMAPINFOHEADER,
    BI_RGB, DIB_RGB_COLORS,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};

pub fn icon_png(path: &str) -> Option<Vec<u8>> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: every handle obtained here is released before returning.
    unsafe {
        let mut info: SHFILEINFOW = zeroed();
        let r = SHGetFileInfoW(
            wide.as_ptr(),
            FILE_ATTRIBUTE_NORMAL,
            &mut info,
            size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_LARGEICON,
        );
        if r == 0 || info.hIcon.is_null() {
            return None;
        }
        let hicon = info.hIcon;
        let mut ii: ICONINFO = zeroed();
        if GetIconInfo(hicon, &mut ii) == 0 {
            DestroyIcon(hicon);
            return None;
        }
        let result = (|| {
            if ii.hbmColor.is_null() {
                return None;
            }
            let mut bm: BITMAP = zeroed();
            if GetObjectW(
                ii.hbmColor,
                size_of::<BITMAP>() as i32,
                &mut bm as *mut _ as *mut _,
            ) == 0
            {
                return None;
            }
            let (w, h) = (bm.bmWidth, bm.bmHeight);
            if !(1..=256).contains(&w) || !(1..=256).contains(&h) {
                return None;
            }
            let mut bi: BITMAPINFO = zeroed();
            bi.bmiHeader = BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h, // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..zeroed()
            };
            let mut px = vec![0u8; (w * h * 4) as usize];
            let dc = GetDC(std::ptr::null_mut());
            let lines = GetDIBits(
                dc,
                ii.hbmColor,
                0,
                h as u32,
                px.as_mut_ptr() as *mut _,
                &mut bi,
                DIB_RGB_COLORS,
            );
            ReleaseDC(std::ptr::null_mut(), dc);
            if lines == 0 {
                return None;
            }
            // BGRA → RGBA. Icons without an alpha channel report alpha 0
            // everywhere; show them opaque rather than invisible.
            let has_alpha = px.as_chunks::<4>().0.iter().any(|p| p[3] != 0);
            for p in px.as_chunks_mut::<4>().0 {
                p.swap(0, 2);
                if !has_alpha {
                    p[3] = 255;
                }
            }
            let mut out = Vec::new();
            {
                let mut enc = png::Encoder::new(&mut out, w as u32, h as u32);
                enc.set_color(png::ColorType::Rgba);
                enc.set_depth(png::BitDepth::Eight);
                let mut wr = enc.write_header().ok()?;
                wr.write_image_data(&px).ok()?;
            }
            Some(out)
        })();
        if !ii.hbmColor.is_null() {
            DeleteObject(ii.hbmColor);
        }
        if !ii.hbmMask.is_null() {
            DeleteObject(ii.hbmMask);
        }
        DestroyIcon(hicon);
        result
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn notepad_icon_is_png() {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
        let png = super::icon_png(&format!(r"{windir}\System32\notepad.exe")).expect("icon");
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    }
}
