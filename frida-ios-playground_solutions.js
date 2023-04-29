// My solutions to challenges at https://github.com/NVISOsecurity/frida-ios-playground

// NB: sometimes, different challenges requre hooking the same funcitons.
// You should comment out the code for the solution that you are not interested in.

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

}

