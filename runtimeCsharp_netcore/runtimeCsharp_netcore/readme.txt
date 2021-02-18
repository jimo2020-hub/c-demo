工程为：C#调用slm_runtime.dll工程
SSHelp.cs SSErrorCode.cs SSDefine.cs runtimeCsharp.cs 文件为函数定义与声明
Program.cs 文件是测试程序主函数。
例子实现：Csharp回调及标准函数调用

需要在bin目录下创建x86/x64两个目录， 分别存放 
	slm_runtime.dll（(release) 
	slm_runtime_dev.dll(debug,发布软件时不要带有该库，只供调用用) 
	slm_runtime.so / slm_runtime_dev.so
	