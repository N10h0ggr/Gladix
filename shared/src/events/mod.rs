// inside src/events/mod.rs
pub mod callbacks;
pub mod event;
pub mod hook;
pub mod scanner;
mod dispatcher;

use crate::events::callbacks::{ImageLoadEvent, ProcessEvent, RegistryEvent};
use crate::events::hook::HookEvent;
use crate::events::scanner::FileScannerEvent;
pub use event::event::Kind as EventKind;
pub use event::Event;

// Helpers to wrap child messages into the top-level Event envelope. This keeps call sites simple
// and consistent: producers can call `.into()` or one of the explicit constructors below without
// importing the `event::Kind` enum each time. This is defined in mod.rs to not lose it when prost
// recompiles events.rs
impl Event {
    /// Wraps a HookEvent into a top-level Event.
    ///
    /// Parameters:
    /// - `h`: owned HookEvent.
    ///
    /// Returns:
    /// - Event with `kind = Hook(h)`.
    ///
    /// Precautions:
    /// - Prefer moving when possible to avoid clones on the hot path.
    #[inline]
    pub fn from_hook(h: HookEvent) -> Self {
        Self { kind: Some(EventKind::Hook(h)) }
    }

    /// Wraps a FileScannerEvent into a top-level Event.
    #[inline]
    pub fn from_scanner(s: FileScannerEvent) -> Self {
        Self { kind: Some(EventKind::Scanner(s)) }
    }

    /// Wraps a ProcessEvent into a top-level Event.
    #[inline]
    pub fn from_process(p: ProcessEvent) -> Self {
        Self { kind: Some(EventKind::ProcessEvent(p)) }
    }

    /// Wraps an ImageLoadEvent into a top-level Event.
    #[inline]
    pub fn from_image_load(il: ImageLoadEvent) -> Self {
        Self { kind: Some(EventKind::ImageLoad(il)) }
    }

    /// Wraps a RegistryEvent into a top-level Event.
    #[inline]
    pub fn from_registry(r: RegistryEvent) -> Self {
        Self { kind: Some(EventKind::Registry(r)) }
    }

    /// Cloning convenience for HookEvent when only a reference is available.
    ///
    /// Precautions:
    /// - Use the owned versions above when you control the call site. Cloning is acceptable for
    ///   occasional paths (tests, replay) but avoid it in tight loops.
    #[inline]
    pub fn from_hook_ref(h: &HookEvent) -> Self {
        Self::from_hook(h.clone())
    }

    /// Cloning convenience for FileScannerEvent.
    #[inline]
    pub fn from_scanner_ref(s: &FileScannerEvent) -> Self {
        Self::from_scanner(s.clone())
    }

    /// Cloning convenience for ProcessEvent.
    #[inline]
    pub fn from_process_ref(p: &ProcessEvent) -> Self {
        Self::from_process(p.clone())
    }

    /// Cloning convenience for ImageLoadEvent.
    #[inline]
    pub fn from_image_load_ref(il: &ImageLoadEvent) -> Self {
        Self::from_image_load(il.clone())
    }

    /// Cloning convenience for RegistryEvent.
    #[inline]
    pub fn from_registry_ref(r: &RegistryEvent) -> Self {
        Self::from_registry(r.clone())
    }
}

// Idiomatic conversions: enable `let e: Event = child.into();` at call sites.
impl From<HookEvent> for Event {
    #[inline]
    fn from(h: HookEvent) -> Self {
        Event::from_hook(h)
    }
}

impl From<&HookEvent> for Event {
    #[inline]
    fn from(h: &HookEvent) -> Self {
        Event::from_hook_ref(h)
    }
}

impl From<FileScannerEvent> for Event {
    #[inline]
    fn from(s: FileScannerEvent) -> Self {
        Event::from_scanner(s)
    }
}

impl From<&FileScannerEvent> for Event {
    #[inline]
    fn from(s: &FileScannerEvent) -> Self {
        Event::from_scanner_ref(s)
    }
}

impl From<ProcessEvent> for Event {
    #[inline]
    fn from(p: ProcessEvent) -> Self {
        Event::from_process(p)
    }
}

impl From<&ProcessEvent> for Event {
    #[inline]
    fn from(p: &ProcessEvent) -> Self {
        Event::from_process_ref(p)
    }
}

impl From<ImageLoadEvent> for Event {
    #[inline]
    fn from(il: ImageLoadEvent) -> Self {
        Event::from_image_load(il)
    }
}

impl From<&ImageLoadEvent> for Event {
    #[inline]
    fn from(il: &ImageLoadEvent) -> Self {
        Event::from_image_load_ref(il)
    }
}

impl From<RegistryEvent> for Event {
    #[inline]
    fn from(r: RegistryEvent) -> Self {
        Event::from_registry(r)
    }
}

impl From<&RegistryEvent> for Event {
    #[inline]
    fn from(r: &RegistryEvent) -> Self {
        Event::from_registry_ref(r)
    }
}
