// My solutions to challenges at https://github.com/NVISOsecurity/frida-ios-playground

// NB: sometimes, different challenges requre hooking the same funcitons.
// You should comment out the code for the solution that you are not interested in.

function getConstant(name){
    var pptr = Module.findExportByName(null, name);
    return ObjC.Object(Memory.readPointer(pptr));
}

if (ObjC.available){
	/* ===== */
	/* BASIC */
	/* ===== */

	var vv = ObjC.classes.VulnerableVault;

	/* CHALLENGE 1.01 */
	Interceptor.attach(
		vv["- setSecretInt:"].implementation,
		{
			onEnter(args){
				console.log("SOLUTION1.01: " + args[2]);
			}
		}
	);

	/* CHALLENGE 1.02 */
	Interceptor.attach(
		vv["- setSecretNumber:"].implementation,
		{
			onEnter(args){
				console.log("SOLUTION1.02: " + ObjC.Object(args[2]));
			}
		}
	);

	/* CHALLENGE 1.03 */
	Interceptor.attach(
		vv["- setSecretString:"].implementation,
		{
			onEnter(args){
				console.log("SOLUTION1.03: " + ObjC.Object(args[2]));
			}
		}
	);

	/* CHALLENGE 1.04 */
	Interceptor.attach(
		vv["- winIfTrue:"].implementation,
		{
			onEnter(args){
				args[2] = new NativePointer(0x1);
			}
		}
	);

	/* CHALLENGE 1.05 */
	Interceptor.attach(
		vv["- getSecretString"].implementation,
		{
			onLeave(retval){
				console.log("SOLUTION1.05: " + ObjC.Object(retval));
			}
		}
	);
	
	/* CHALLENGE 1.06 */
	Interceptor.attach(
		vv["- hasWon"].implementation,
		{
			onLeave(retval){
				retval.replace(new NativePointer(0x1));
			}
		}
	);

	/* CHALLENGE 1.07 */
	Interceptor.attach(
		vv["- getSecretKey"].implementation,
		{
			onLeave(retval){
				var data = ObjC.Object(retval);
				console.log("SOLUTION1.07: " + data.bytes().readUtf8String(data.length()));
			}
		}
	);

	/* CHALLENGE 1.08 */
	Interceptor.attach(
		vv["- getself"].implementation,
		{
			onLeave(retval){
				var self = ObjC.Object(retval);
				self.win();
			}
		}
	);

	/* CHALLENGE 1.09 */
	Interceptor.attach(
		vv["- getself"].implementation,
		{
			onLeave(retval){
				var self = ObjC.Object(retval);
				self.winIfFrida_and27042_(
					ObjC.classes.NSString.stringWithUTF8String_(
						Memory.allocUtf8String("Frida")
					), 
					27042
				);
			}
		}
	);

	/* CHALLENGE 1.10 */
	Interceptor.attach(
		vv["- doNothing"].implementation,
		{
			onEnter(){
				ObjC.chooseSync(ObjC.classes.HiddenVault)[0].win();
			}
		}
	);

	/* CHALLENGE 1.11 */
	Interceptor.attach(
		vv["- doNothing"].implementation,
		{
			onEnter(){
				let hiddenVault = ObjC.chooseSync(ObjC.classes.HiddenVault)[0];
				console.log(hiddenVault.$ownMethods);
				hiddenVault['- super_secret_function']();
			}
		}
	);

	/* CHALLENGE 1.12 */
	Interceptor.attach(
		vv["- generateNumbers"].implementation,
		{
			onLeave(retval){
				let array = ObjC.Object(retval);
				let m_array = ObjC.classes.NSMutableArray.new();
				for (let i = 0; i < array.count(); i++){
					let value = array.objectAtIndex_(i);
					if (value > 42){
						m_array.addObject_(42);
					}
					else{
						m_array.addObject_(value);
					}
				}
				retval.replace(m_array);
			}
		}
	);

	/* ======== */
	/* ADVANCED */
	/* ======== */

	/* CHALLENGE 2.01 */
	vv['- lose'].implementation = ObjC.implement(
		vv["- lose"], 
		(vvault, sel) => {
			ObjC.Object(vvault).win();
		}
	);
	
	/* CHALLENGE 2.02 */
	Interceptor.replace(
		vv['- lose'].implementation,
		new NativeCallback(
			(vvault, sel) => {
				ObjC.Object(vvault).win();
			},
			"void",
			["pointer", "pointer"]
		)
	);

	/* CHALLENGE 2.03 */
	var isSecure = Module.findExportByName(null, "isSecure");
	Interceptor.attach(
		isSecure,
		{
			onLeave(retval){
				retval.replace(1);
			}
		}
	);


	/* CHALLENGE 2.04 */
	//TODO

	/* CHALLENGE 2.05 */
	Interceptor.attach(
		Module.findExportByName(null, "getLOTRTrilogy"),
		{
			onLeave(retval){
				console.log(
					retval.add(16).readPointer(8)
					.add(16).readPointer(8)
					.add(8).readPointer(8).readCString()
					);				
			}
		}
	);

	/* CHALLENGE 2.06 */
	var hotPatchMe = Module.findExportByName(null, "hotPatchMe");
	//Get branch instruction
	var instruction = Instruction.parse(hotPatchMe.add(32)); 		
	
	// Change permissions to write to text segment
	Memory.protect(hotPatchMe.add(32), 4, 'rwx');

	// Substitute "b.ne" instruction with "nop"
	hotPatchMe.add(32).writeByteArray([0x1F, 0x20, 0x03, 0xD5]);



	/* ======== */
	/* INTERACT */
	/* ======== */	


	/* CHALLENGE 3.01 */
	Interceptor.attach(
		vv["- doNothing"].implementation,
		{
			onEnter(){
				let uiAlert = ObjC.classes.UIAlertController.alertControllerWithTitle_message_preferredStyle_("Title", "Message", 1);
				let action = ObjC.classes.UIAlertAction.actionWithTitle_style_handler_('OK', 0, null);
				uiAlert.addAction_(action);
				ObjC.classes.UIApplication.sharedApplication()
				.keyWindow().rootViewController().presentViewController_animated_completion_(uiAlert, true, NULL);
			}
		}
	);

	/* CHALLENGE 3.02 */
	Interceptor.attach(
		Module.getExportByName('Security', 'SecItemAdd'),
		{
			onEnter(args){
				let query = ObjC.Object(args[0]);
				let vdata = ObjC.classes.NSDictionary.dictionaryWithDictionary_(query).objectForKey_("v_Data");
				let gena = ObjC.classes.NSDictionary.dictionaryWithDictionary_(query).objectForKey_("gena");
				console.log(`KEY: ${ObjC.classes.NSString.alloc()
					.initWithData_encoding_(gena, 4)}, VALUE: ${ObjC.classes.NSString.alloc()
						.initWithData_encoding_(vdata, 4)}`);
			}
		}
	);

	/* CHALLENGE 3.03 */
	var SecItemCopyMatching = new NativeFunction(Module.getExportByName('Security', 'SecItemCopyMatching'), "int", ["pointer", "pointer"]);
	Interceptor.attach(
		vv["- doNothing"].implementation,
		{
			onEnter(){
				var kCFBooleanTrue = getConstant("kCFBooleanTrue");
				let obj1 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("genp"));
				let obj2 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("VulnerableVaultService"));
				let obj3 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("m_LimitAll"));
				
				let key1 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("class"));
				let key2 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("svce"));
				let key3 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("m_Limit"));
				let key4 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("r_Attributes"));
				let key5 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("r_Data"));
				
				let query = ObjC.classes.NSMutableDictionary.new();
				query.setObject_forKey_(obj1, key1);
				query.setObject_forKey_(obj2, key2);
				query.setObject_forKey_(obj3, key3);
				query.setObject_forKey_(kCFBooleanTrue, key4);
				query.setObject_forKey_(kCFBooleanTrue, key5);
				var res = Memory.alloc(Process.pointerSize)
				SecItemCopyMatching(query, res);
				var pt = Memory.readPointer(res);
            	if (!pt.isNull()) {
					let r_data = new ObjC.Object(pt).objectAtIndex_(0);
					let data = ObjC.classes.NSString.alloc()
						.initWithData_encoding_(r_data.objectForKey_(
							ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("v_Data"))
						), 4);
					let key = ObjC.classes.NSString.alloc()
						.initWithData_encoding_(r_data.objectForKey_(
							ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("acct"))
						), 4);
					console.log(`KEY: ${key}, VALUE: ${data}`);
				}
			}
		}
	);
	

	/* CHALLENGE 3.04 */
	var auth = vv['- authenticate'].implementation;
	// TODO

	
	/* CHALLENGE 3.05 */
	Interceptor.attach(
		ObjC.classes.NSUserDefaults['- setObject:forKey:'].implementation,
		{
			onEnter(args){
				console.log(`KEY: ${ObjC.Object(args[3])}, VALUE: ${ObjC.Object(args[2])}`);
			}
		}
	);

	/* CHALLENGE 3.06 */
	Interceptor.attach(
		vv["- doNothing"].implementation,
		{
			onEnter(args){
				console.log(
					ObjC.classes.NSUserDefaults.standardUserDefaults().dictionaryRepresentation()
				);
			}
		}
	);



	/* ========== */
	/* FRIDA / JB */
	/* ========== */	
	
	/* CHALLENGE 4.01 */
	Interceptor.attach(
		Module.getExportByName(null, 'bind'),
		{
			onLeave(retval){
				retval.replace(new NativePointer(0x0))
			}
		}
	);

	/* CHALLENGE 4.02 */
	var clearLib;
	Interceptor.attach(
		Module.getExportByName(null, '_dyld_get_image_name'),
		{
			onLeave(retval){
				let s1 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("MobileSubstrate"));
				let s2 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("libcycript"));
				let s3 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("SubstrateLoader"));
				let s4 = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String("SubstrateInserter"));
				let lib = ObjC.classes.NSString.stringWithCString_encoding_(retval, 4);
				if (lib.containsString_(s1) || lib.containsString_(s2) || lib.containsString_(s3) || lib.containsString_(s4)){
					var s = Memory.allocUtf8String("Hi");
					retval.replace(s);
				}
			}
		}
	);

	/* CHALLENGE 4.02 */
	// TODO

	/* ===== */
	/* SWIFT */
	/* ===== */

	/* CHALLENGE 5.01 */
	Interceptor.attach(
		Swift.classes.SwiftVault.$methods.filter(f => f.name.includes("getSmallSecret"))[0].address,
		{
			onLeave(retval){
				let finalString = Memory.alloc(16);
				// String is splitted between x0 and x1
				let c = this.context.x0.toInt32();
				var char;
				for (let i = 0; i < 4 && char != 0; i++){
					char = (c & (0xFF << 8*i)) >> 8 * i;
					finalString.add(i).writeU8(char); 
				}

				if (char == 0){
					console.log("SHORT STRING: " + finalString.readCString());
				}
				else{
					c = this.context.x0.shr(32).toInt32();
					for (let i = 0; i < 4 && char != 0; i++){
						char = (c & (0xFF << 8*i)) >> 8 * i;
						finalString.add(4+i).writeU8(char); 
					}
					if (char == 0){
						console.log("SHORT STRING: " + finalString.readCString());
					}
					else{
						c = this.context.x1.toInt32();
						for (let i = 0; i < 4 && char != 0; i++){
							char = (c & (0xFF << 8*i)) >> 8 * i;
							finalString.add(8+i).writeU8(char); 
						}
						if (char == 0){
							console.log("SHORT STRING: " + finalString.readCString());
						}
						else{
							c = this.context.x1.shr(32).toInt32();
							for (let i = 0; i < 4 && char != 0; i++){
								char = (c & (0xFF << 8*i)) >> 8 * i;
								finalString.add(12+i).writeU8(char); 
							}
							if (char == 0){
								console.log("SHORT STRING: " + finalString.readCString());
							}
						}
					}
				}
			}
		}
	);


	/* CHALLENGE 5.02 */
	// TODO
}



