using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using SLM_HANDLE_INDEX = System.UInt32;
namespace SenseShield
{
    class Program
    {
        public const int DEVICE_SN_LENGTH = 16;

        //打印方式定义
        public static void WriteLineGreen(string s)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(s);
            Console.ResetColor();
        }
        public static void WriteLineRed(string s)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(s);
            Console.ResetColor();
        }
        public static void WriteLineYellow(string s)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(s);
            Console.ResetColor();
        }
        public static byte[] StringToHex(string HexString)
        {
            byte[] returnBytes = new byte[HexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(HexString.Substring(i * 2, 2), 16);

            return returnBytes;
        }

        //回调函数信息提示
        public static uint handle_service_msg(uint message, UIntPtr wparam, UIntPtr lparam)
        {
            uint ret = SSErrCode.SS_OK;
            string StrMsg = string.Empty;
            char[] szmsg = new char[1024];
            char[] lock_sn = new char[DEVICE_SN_LENGTH];
            char[] szlock_sn = new char[DEVICE_SN_LENGTH];

            switch (message)
            {
                case SSDefine.SS_ANTI_INFORMATION:   // 信息提示
                    StrMsg = string.Format("SS_ANTI_INFORMATION is:0x{0:X8} wparam is %p", message, wparam);
                    WriteLineRed(StrMsg);
                    break;
                case SSDefine.SS_ANTI_WARNING:       // 警告
                    // 反调试检查。一旦发现如下消息，建议立即停止程序正常业务，防止程序被黑客调试。

                    switch ((uint)(wparam))
                    {
                        case SSDefine.SS_ANTI_PATCH_INJECT:
                            StrMsg = string.Format("信息类型=:0x{0:X8} 具体错误码= 0x{0:X8}", "注入", message, wparam);
                             WriteLineRed(StrMsg);
                            break;
                        case SSDefine.SS_ANTI_MODULE_INVALID:
                            StrMsg = string.Format("信息类型=:0x{0:X8} 具体错误码= 0x{0:X8}", "非法模块DLL", message, wparam);
                             WriteLineRed(StrMsg);
                            break;
                        case SSDefine.SS_ANTI_ATTACH_FOUND:
                            StrMsg = string.Format("信息类型=:0x{0:X8} 具体错误码= 0x{0:X8}", "附加调试", message, wparam);
                             WriteLineRed(StrMsg);
                            break;
                        case SSDefine.SS_ANTI_THREAD_INVALID:
                             StrMsg = string.Format("信息类型=:0x{0:X8} 具体错误码= 0x{0:X8}", "线程非法", message, wparam);
                             WriteLineRed(StrMsg);
                            break;
                        case SSDefine.SS_ANTI_THREAD_ERROR:
                             StrMsg = string.Format("信息类型=:0x{0:X8} 具体错误码= 0x{0:X8}", "线程错误", message, wparam);
                             WriteLineRed(StrMsg);
                            break;
                        case SSDefine.SS_ANTI_CRC_ERROR:
                             StrMsg = string.Format("信息类型=:0x{0:X8} 具体错误码= 0x{0:X8}", "内存模块 CRC 校验", message, wparam);
                             WriteLineRed(StrMsg); 
                            break;
                        case SSDefine.SS_ANTI_DEBUGGER_FOUND:
                             StrMsg = string.Format("信息类型=:0x{0:X8} 具体错误码= 0x{0:X8}", "发现调试器", message, wparam);
                             WriteLineRed(StrMsg); 
                            break;
                        default:
                             StrMsg = string.Format("信息类型=:0x{0:X8} 具体错误码= 0x{0:X8}", "其他未知错误", message, wparam);
                             WriteLineRed(StrMsg);
                            break;
                    }
                    break;
                case SSDefine.SS_ANTI_EXCEPTION:         // 异常
                    StrMsg = string.Format("SS_ANTI_EXCEPTION is :0x{0:X8} wparam is %p", message, wparam);
                      WriteLineRed(StrMsg);;
                    break;
                case SSDefine.SS_ANTI_IDLE:              // 暂保留
                    StrMsg = string.Format("SS_ANTI_IDLE is :0x{0:X8} wparam is %p", message, wparam);
                      WriteLineRed(StrMsg); 
                    break;
                case SSDefine.SS_MSG_SERVICE_START:      // 服务启动
                    StrMsg = string.Format("SS_MSG_SERVICE_START is :0x{0:X8} wparam is %p", message, wparam);
                      WriteLineRed(StrMsg);
                    break;
                case SSDefine.SS_MSG_SERVICE_STOP:       // 服务停止
                    StrMsg = string.Format("SS_MSG_SERVICE_STOP is :0x{0:X8} wparam is %p", message, wparam);
                      WriteLineRed(StrMsg);
                    break;
                case SSDefine.SS_MSG_LOCK_AVAILABLE:     // 锁可用（插入锁或SS启动时锁已初始化完成），wparam 代表锁号
                    // 锁插入消息，可以根据锁号查询锁内许可信息，实现自动登录软件等功能。
                    StrMsg = string.Format("{0},{0:x8}锁插入", DateTime.Now.ToString(),wparam);
                    WriteLineRed(StrMsg);
                    break;
                case SSDefine.SS_MSG_LOCK_UNAVAILABLE:   // 锁无效（锁已拔出），wparam 代表锁号
                    // 锁拔出消息，对于只使用锁的应用程序，一旦加密锁拔出软件将无法继续使用，建议发现此消息提示用户保存数据，程序功能锁定等操作。
                    StrMsg = string.Format("{0},{0:x8}锁拔出", DateTime.Now.ToString(), wparam);
                    WriteLineRed(StrMsg);
                    break;
            }
            // 输出格式化后的消息内容
            //printf("%s\n", szmsg);
            return ret;
        }

        //main方法，测试主程序
        static void Main(string[] args)
        {
            
            uint ret = 0;
            SLM_HANDLE_INDEX Handle = 0;
            callback pfn;
            string StrMsg = string.Empty;
            IntPtr a = IntPtr.Zero;

            //01. init
            ST_INIT_PARAM initPram = new ST_INIT_PARAM();
            initPram.version =SSDefine.SLM_CALLBACK_VERSION02;
            initPram.flag = SSDefine.SLM_INIT_FLAG_NOTIFY;
            pfn = new callback(handle_service_msg);
            initPram.pfn = pfn;
            initPram.password = StringToHex("D7AA1DEE3495FAA0E81161FABB752687");
            ret = SlmRuntime.slm_init(ref initPram);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("Slm_Init Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                WriteLineGreen("Slminit Success!");
            }

            //02. find License
            IntPtr desc = IntPtr.Zero;
            ret = SlmRuntime.slm_find_license(1, INFO_FORMAT_TYPE.JSON, ref desc);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_find_license Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                string StrPrint = Marshal.PtrToStringAnsi(desc);
                WriteLineYellow(StrPrint);
                WriteLineGreen("SlmFindLicenseEasy Success!");
                SlmRuntime.slm_free(desc);
                if (ret != SSErrCode.SS_OK)
                {
                    StrMsg = string.Format("slm_free Failure:0x{0:X8}", ret);
                    WriteLineRed(StrMsg);
                }
            }


            //03. LOGIN
            ST_LOGIN_PARAM stLogin = new ST_LOGIN_PARAM();
            stLogin.size = (UInt32)Marshal.SizeOf(stLogin);
            stLogin.license_id = 5;
            stLogin.login_mode = SSDefine.SLM_LOGIN_MODE_LOCAL;
            ret = SlmRuntime.slm_login(ref stLogin, INFO_FORMAT_TYPE.STRUCT, ref Handle, a);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("Slm_Login Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                WriteLineGreen("Slmlogin Success!");
            }

            //04. KEEP ALIVE
            ret = SlmRuntime.slm_keep_alive(Handle);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("SlmKeepAliveEasy Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
                System.Diagnostics.Debug.Assert(true);
            }
            else
            {
                WriteLineGreen("SlmKeepAliveEasy Success!");
            }

            //05. get_info
            //lock_info
            ret = SlmRuntime.slm_get_info(Handle, INFO_TYPE.LOCK_INFO, INFO_FORMAT_TYPE.JSON, ref desc);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_get_info(local_info) Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                string StrPrint = Marshal.PtrToStringAnsi(desc);
                WriteLineYellow(StrPrint);
                WriteLineGreen("slm_get_info(local_info) Success!");
                if (ret != SSErrCode.SS_OK)
                {
                    StrMsg = string.Format("slm_free Failure:0x{0:X8}", ret);
                    WriteLineRed(StrMsg);
                }
            }
            //session_info
            ret = SlmRuntime.slm_get_info(Handle, INFO_TYPE.SESSION_INFO, INFO_FORMAT_TYPE.JSON, ref desc);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_get_info(session_info) Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                string StrPrint = Marshal.PtrToStringAnsi(desc);
                WriteLineYellow(StrPrint);
                WriteLineGreen("slm_get_info(session_info) Success!");
                if (ret != SSErrCode.SS_OK)
                {
                    StrMsg = string.Format("slm_free Failure:0x{0:X8}", ret);
                    WriteLineRed(StrMsg);
                }
            }
            //license_info
            ret = SlmRuntime.slm_get_info(Handle, INFO_TYPE.LICENSE_INFO, INFO_FORMAT_TYPE.JSON, ref desc);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_get_info(license_info) Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                string StrPrint = Marshal.PtrToStringAnsi(desc);
                WriteLineYellow(StrPrint);
                WriteLineGreen("slm_get_info(license_info) Success!");
                if (ret != SSErrCode.SS_OK)
                {
                    StrMsg = string.Format("slm_free Failure:0x{0:X8}", ret);
                    WriteLineRed(StrMsg);
                }
            }

            //07 08. slm_encrypt  slm_decrypt
            //slm_encrypt
            string StrData = "test data.......";
            byte[] Data = System.Text.ASCIIEncoding.Default.GetBytes(StrData);
            byte[] Enc = new byte[StrData.Length];
            byte[] Dec = new byte[StrData.Length];

            WriteLineYellow(string.Format("[Before the encryption DATA]:{0}", StrData));
            ret = SlmRuntime.slm_encrypt(Handle, Data, Enc, (uint)StrData.Length);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_encrypt Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                WriteLineYellow(string.Format("[encrypted DATA]:{0}", System.Text.ASCIIEncoding.Default.GetString(Enc)));
                WriteLineGreen("slm_encrypt Success!");
            }
            //slm_decrypt
            ret = SlmRuntime.slm_decrypt(Handle, Enc, Dec, (uint)StrData.Length);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_decrypt Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                WriteLineYellow(string.Format("[decrypted DATA]:{0}", System.Text.ASCIIEncoding.Default.GetString(Dec)));
                WriteLineGreen("slm_decrypt Success!");
            }

            //09. 10. 11.  slm_user_data_getsize slm_user_data_read  slm_user_data_write
            //slm_user_data_getsize
            UInt32 dataSize = 0;
            ret = SlmRuntime.slm_user_data_getsize(Handle, LIC_USER_DATA_TYPE.RAW, ref dataSize);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_user_data_getsize Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                WriteLineGreen("slm_user_data_getsize Success!");
                if (dataSize > 0)
                {
                    //slm_user_data_read
                    byte[] readbuf = new byte[dataSize];
                    ret = SlmRuntime.slm_user_data_read(Handle, LIC_USER_DATA_TYPE.RAW, readbuf, 0, dataSize);
                    if (ret != SSErrCode.SS_OK)
                    {
                        StrMsg = string.Format("slm_user_data_read Failure:0x{0:X8}", ret);
                        WriteLineRed(StrMsg);
                    }
                    else
                    {

                        //判断数据是否为空，空写入数据，否则输出内容
                        UInt32 flag = 0;
                        for (int i = 0; i < readbuf.Length; i++)
                        {
                            if (readbuf[i] == 0)
                                flag = 1;
                            else
                                flag = 2;
                        }
                        if (flag == 1)
                        {
                            //slm_user_data_write
                            string buf = "";//输入要写入数据区内容
                            byte[] writebuf = System.Text.ASCIIEncoding.Default.GetBytes(buf);
                            ret = SlmRuntime.slm_user_data_write(Handle, writebuf, 0, (UInt32)buf.Length);
                            if (ret != SSErrCode.SS_OK)
                            {
                                StrMsg = string.Format("slm_user_data_write Failure:0x{0:X8}", ret);
                                WriteLineRed(StrMsg);
                            }
                            else
                            {
                                WriteLineYellow(string.Format("[Write RAW DATA]:{0}", writebuf));
                                WriteLineGreen("slm_user_data_write Success!");
                            }
                        }
                        else if (flag == 2)
                        {
                            WriteLineYellow(string.Format("[Read RAW DATA]:{0}", System.Text.ASCIIEncoding.Default.GetString(readbuf)));
                        }
                        WriteLineGreen("slm_user_data_read Success!");
                    }
                }
                else
                {
                    WriteLineYellow(string.Format("[No data area]:{0}", dataSize));
                }
            }

            ////12. 13. 14. 15. 16 slm_mem_alloc - slm_mem_write -slm_mem_read - slm_mem_free
            //slm_mem_alloc
            UInt32 mem_index = 0;
            ret = SlmRuntime.slm_mem_alloc(Handle, 1024, ref mem_index);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_mem_alloc Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                WriteLineYellow(string.Format("[mem_index ]:{0}", mem_index));
                WriteLineGreen("slm_mem_alloc Success!");
            }
            //slm_mem_write
            string mem_buff = "test memory data...";
            UInt32 mem_size = (UInt32)mem_buff.Length;
            UInt32 mem_len = 0;
            byte[] mem_write_buf = System.Text.ASCIIEncoding.Default.GetBytes(mem_buff);
            byte[] mem_read_buf = new byte[mem_size];


            ret = SlmRuntime.slm_mem_write(Handle, mem_index, 0, mem_size, mem_write_buf, ref mem_len);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_mem_write Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
                System.Diagnostics.Debug.Assert(true);
            }
            else
            {
                WriteLineYellow(string.Format("[Mem Write]:{0}", mem_buff));
                WriteLineGreen("slm_mem_write Success!");
            }
            //slm_mem_read
            ret = SlmRuntime.slm_mem_read(Handle, mem_index, 0, mem_size, mem_read_buf, ref mem_len);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_mem_write Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
                System.Diagnostics.Debug.Assert(true);
            }
            else
            {
                string StrPrint = string.Format("[Mem Read]:{0}", System.Text.ASCIIEncoding.Default.GetString(mem_read_buf));
                WriteLineYellow(StrPrint);
                WriteLineGreen("slm_mem_write Success!");
            }
            //slm_mem_free
            ret = SlmRuntime.slm_mem_free(Handle, mem_index);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_mem_write Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
                System.Diagnostics.Debug.Assert(true);
            }
            else
            {
                WriteLineGreen("slm_mem_write Success!");
            }

            //17 slm_logout
            ret = SlmRuntime.slm_logout(Handle);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_logout Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                WriteLineGreen("slm_logout Success!");
            }

            //18. slm_error_format
            IntPtr result;
            result = SlmRuntime.slm_error_format(ret, SSDefine.LANGUAGE_CHINESE_ASCII);
            if (result != IntPtr.Zero)
            {
                string error = Marshal.PtrToStringAnsi(result);
                StrMsg = string.Format("slm_error_format success: {0}, 0x{1:X8}", error, ret);
                WriteLineGreen(StrMsg);
            }
            else
            {
                WriteLineRed("slm_error_format Failure!");
            }

            //19. slm_get_developer_id
            byte[] developer_id = new byte[8];
            ret = SlmRuntime.slm_get_developer_id(developer_id);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_get_developer_id Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                string StrPrint = string.Format("[developer_id]:{0}", System.Text.ASCIIEncoding.Default.GetString(developer_id));
                WriteLineYellow(StrPrint);
                WriteLineGreen("slm_get_developer_id Success!");
            }

            //20. slm_get_version
            UInt32 api_version = 0;
            UInt32 ss_version = 0;
            ret = SlmRuntime.slm_get_version(ref api_version, ref ss_version);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_get_version Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                StrMsg = string.Format("api_version :0x{0:X8},ss_version:0X{0:X8}", api_version, ss_version);
                WriteLineYellow(StrMsg);
                WriteLineGreen("slm_get_version Success!");
            }

            //21. slm_enum_device
            IntPtr device_info = IntPtr.Zero;
            ret = SlmRuntime.slm_enum_device(ref device_info);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_enum_device Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                string StrPrint = Marshal.PtrToStringAnsi(device_info);
                WriteLineYellow(StrPrint);
                WriteLineGreen("slm_enum_device Success!");
            }

            //22. slm_enum_license_id
            IntPtr license_ids = IntPtr.Zero;
            string dev_info = Marshal.PtrToStringAnsi(device_info);
            JArray arrDeviceInfo = (JArray)JsonConvert.DeserializeObject(dev_info);
            for (int i = 0; i < arrDeviceInfo.Count; i++)
            {
                string Info = arrDeviceInfo[i].ToString();
                ret = SlmRuntime.slm_enum_license_id(Info, ref license_ids);
                if (ret != SSErrCode.SS_OK)
                {
                    StrMsg = string.Format("slm_enum_license_id Failure:0x{0:X8}", ret);
                    WriteLineRed(StrMsg);
                }
                else
                {
                    string StrPrint = Marshal.PtrToStringAnsi(license_ids);
                    WriteLineYellow(StrPrint);
                    WriteLineGreen("slm_enum_license_id Success!");
                }

                //23. slm_get_license_info,举例0号许可
                IntPtr license_info = IntPtr.Zero;
                ret = SlmRuntime.slm_get_license_info(Info, 0, ref license_info);
                if (ret != SSErrCode.SS_OK)
                {
                    StrMsg = string.Format("slm_get_license_info Failure:0x{0:X8}", ret);
                    WriteLineRed(StrMsg);
                }
                else
                {
                    string StrPrint = Marshal.PtrToStringAnsi(license_info);
                    WriteLineYellow(StrPrint);
                    WriteLineGreen("slm_get_license_info Success!");
                }
            }

            //24. slm_cleanup
            ret = SlmRuntime.slm_cleanup();
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_cleanup Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                WriteLineGreen("slm_cleanup Success!");
            }

            Console.ReadKey();
        }
    }
}
