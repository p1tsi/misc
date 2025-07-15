/*
 * WhereAmIReally
 *
 * As the other challenges, I solved this in a macOS VM.
 * For this reason, the jailbreak detection logic is completely bypassed.
 * (but it was sufficient to hook '-[NSFileManager fileExistsAtPath:]' method
 * and let it return false to bypass it, because the jailbreak detection logic 
 * check if some jailbreak-related files are present in the filesystem).
 *
 * Since the VM is not able to retrieve GPS location data, I simulated the 
 * position update with this script. The flag is reported in the screenshot
 * (even if it seems not to be 'CTF{...}' format)
 *
 * Cheers
 *
**/

var loc = ObjC.classes.CLLocation.alloc().initWithLatitude_longitude_(0x404888888, 0x40029999)
var ar = ObjC.classes.NSMutableArray.new()

ar.addObject_(loc)

var wlm = ObjC.chooseSync(ObjC.classes.CLLocationManager)[0].delegate()
wlm.locationManager_didUpdateLocations_(ObjC.chooseSync(ObjC.classes.CLLocationManager)[0], ar)
