import AppKit
import CoreServices

enum SettingsLaunch {
    static func shouldShowWindow(defaultLaunch: Bool, event: NSAppleEventDescriptor?) -> Bool {
        let origin = event?.paramDescriptor(forKeyword: AEKeyword(keyAEPropData))?.enumCodeValue
        return defaultLaunch && origin != keyAELaunchedAsLogInItem && origin != keyAELaunchedAsServiceItem
    }
}
