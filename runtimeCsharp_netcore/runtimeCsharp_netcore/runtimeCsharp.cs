using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using SLM_HANDLE_INDEX = System.UInt32;
namespace SenseShield
{
    public delegate uint callback(uint message, UIntPtr wparam, UIntPtr lparam);
    //init struct
    public struct ST_INIT_PARAM
    {
        /** 版本－用来兼容，当前使用 SLM_CALLBACK_VERSION02 */
        public UInt32 version;
        /** 如果需要接收SenseShield服务通知，填 SLM_INIT_FLAG_NOTIFY */
        public UInt32 flag;
        /** 回调函数指针*/
        [MarshalAs(UnmanagedType.FunctionPtr)]
        public callback pfn;
        /** 通信连接超时时间（毫秒），如果填0，则使用默认超时时间（7秒）*/
        public UInt32 timeout;
        /** API密码，可从深思云开发者中心（https://developer.senseyun.com），通过“查看开发商信息”获取*/
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)SSDefine.SLM_DEV_PASSWORD_LENGTH)]
        public byte[] password;
    }
    /** 设备证书类型*/
    public enum CERT_TYPE : uint
    {
        /** 证书类型：根证书  */
        CERT_TYPE_ROOT_CA = 0,
        /** 证书类型：设备子CA  */
        CERT_TYPE_DEVICE_CA = 1,
        /** 证书类型：设备证书  */
        CERT_TYPE_DEVICE_CERT = 2,
        /** 证书类型：深思设备证书  */
        CERT_TYPE_SENSE_DEVICE_CERT = 3,
    }
    internal class SlmRuntime
    {
        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //public delegate UInt32 SSRuntimeCallBack(UInt32 message, IntPtr wparam, IntPtr lparam);
        private static bool Is64 = IntPtr.Size == 8 ? true : false;
#if DEBUG

        const string lib_name32 = "x86/slm_runtime_dev";
        const string lib_name64 = "x64/slm_runtime_dev";
#else
        const string lib_name32 = "x86/slm_runtime";
        const string lib_name64 = "x64/slm_runtime";
#endif
        /// <summary>
        /// Runtime API初始化函数，调用所有Runtime API必须先调用此函数进行初始化
        /// </summary>
        ///  <param name="init_param"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#1", CallingConvention = CallingConvention.StdCall)]
        internal static extern UInt32 slm_init32_windows(ref ST_INIT_PARAM initParam);
        [DllImport(lib_name64, EntryPoint = "#1", CallingConvention = CallingConvention.StdCall)]
        internal static extern UInt32 slm_init64_windows(ref ST_INIT_PARAM initParam);
        [DllImport(lib_name32, EntryPoint = "slm_init")]
        internal static extern UInt32 slm_init32_linux(ref ST_INIT_PARAM initParam);
        [DllImport(lib_name64, EntryPoint = "slm_init")]
        internal static extern UInt32 slm_init64_linux(ref ST_INIT_PARAM initParam);

        internal static UInt32 slm_init(ref ST_INIT_PARAM initParam)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_init64_windows(ref initParam);
                }
                return SlmRuntime.slm_init32_windows(ref initParam);
            }
            else 
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_init64_linux(ref initParam);
                }
                return SlmRuntime.slm_init32_linux(ref initParam);
            }
        }

        /// <summary>
        /// 列举锁内某id许可
        /// </summary>
        /// <param name="license_id"></param>
        /// <param name="format"></param>
        /// <param name="license_desc"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#2", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_find_license32_windows(
                    UInt32 license_id,
                    INFO_FORMAT_TYPE format,
                    ref IntPtr license_desc);
        [DllImport(lib_name64, EntryPoint = "#2", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_find_license64_windows(
                    UInt32 license_id,
                    INFO_FORMAT_TYPE format,
                    ref IntPtr license_desc);

        [DllImport(lib_name32, EntryPoint = "slm_find_license")]
        public static extern UInt32 slm_find_license32_linux(
                    UInt32 license_id,
                    INFO_FORMAT_TYPE format,
                    ref IntPtr license_desc);
        [DllImport(lib_name64, EntryPoint = "slm_find_license")]
        public static extern UInt32 slm_find_license64_linux(
                    UInt32 license_id,
                    INFO_FORMAT_TYPE format,
                    ref IntPtr license_desc);
        internal static UInt32 slm_find_license(
                    UInt32 license_id,
                    INFO_FORMAT_TYPE format,
                    ref IntPtr license_desc)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_find_license64_windows(license_id, format, ref license_desc);
                }
                return SlmRuntime.slm_find_license32_windows(license_id, format, ref license_desc);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_find_license64_linux(license_id, format, ref license_desc);
                }
                return SlmRuntime.slm_find_license32_linux(license_id, format, ref license_desc);
            }
        }
        /// <summary>
        /// 安全登录许可
        /// </summary>
        /// <param name="license_param"></param>
        /// <param name="param_format"></param>
        /// <param name="slm_handle"></param>
        /// <param name="auth"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#3", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_login32_windows(
                    ref ST_LOGIN_PARAM license_param,
                    INFO_FORMAT_TYPE param_format,
                    ref SLM_HANDLE_INDEX slm_handle,
                    IntPtr auth);
        [DllImport(lib_name64, EntryPoint = "#3", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_login64_windows(
                    ref ST_LOGIN_PARAM license_param,
                    INFO_FORMAT_TYPE param_format,
                    ref SLM_HANDLE_INDEX slm_handle,
                    IntPtr auth);
        [DllImport(lib_name32, EntryPoint = "slm_login")]
        public static extern UInt32 slm_login32_linux(
            ref ST_LOGIN_PARAM license_param,
            INFO_FORMAT_TYPE param_format,
            ref SLM_HANDLE_INDEX slm_handle,
            IntPtr auth);
        [DllImport(lib_name64, EntryPoint = "slm_login")]
        public static extern UInt32 slm_login64_linux(
                    ref ST_LOGIN_PARAM license_param,
                    INFO_FORMAT_TYPE param_format,
                    ref SLM_HANDLE_INDEX slm_handle,
                    IntPtr auth);
        internal static UInt32 slm_login(
                    ref ST_LOGIN_PARAM license_param,
                    INFO_FORMAT_TYPE param_format,
                    ref SLM_HANDLE_INDEX slm_handle,
                    IntPtr auth)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_login64_windows(ref license_param, param_format, ref slm_handle, auth);
                }
                return SlmRuntime.slm_login32_windows(ref license_param, param_format, ref slm_handle, auth);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_login64_linux(ref license_param, param_format, ref slm_handle, auth);
                }
                return SlmRuntime.slm_login32_linux(ref license_param, param_format, ref slm_handle, auth);
            }
            
        }
        /// <summary>
        /// 枚举已登录的用户token
        /// </summary>
        /// <param name="access_token">默认用户的token，指向一个字符串的IntPtr</param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#4", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_cloud_token32_windows(
                    ref IntPtr access_token);
        [DllImport(lib_name64, EntryPoint = "#4", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_cloud_token64_windows(
                    ref IntPtr access_token);
        [DllImport(lib_name32, EntryPoint = "slm_get_cloud_token")]
        public static extern UInt32 slm_get_cloud_token32_linux(
            ref IntPtr access_token);
        [DllImport(lib_name64, EntryPoint = "slm_get_cloud_token")]
        public static extern UInt32 slm_get_cloud_token64_linux(
                    ref IntPtr access_token);
        internal static UInt32 slm_get_cloud_token(
                    ref IntPtr access_token)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_cloud_token64_windows(ref access_token);
                }
                return SlmRuntime.slm_get_cloud_token32_windows(ref access_token);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_cloud_token64_linux(ref access_token);
                }
                return SlmRuntime.slm_get_cloud_token32_linux(ref access_token);
            }
        }
        /// <summary>
        /// 许可登出，并且释放许可句柄等资源
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#5", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_logout32_windows(
                    SLM_HANDLE_INDEX slm_handle);
        [DllImport(lib_name64, EntryPoint = "#5", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_logout64_windows(
                    SLM_HANDLE_INDEX slm_handle);
        [DllImport(lib_name32, EntryPoint = "slm_logout")]
        public static extern UInt32 slm_logout32_linux(
            SLM_HANDLE_INDEX slm_handle);
        [DllImport(lib_name64, EntryPoint = "slm_logout")]
        public static extern UInt32 slm_logout64_linux(
                    SLM_HANDLE_INDEX slm_handle);
        internal static UInt32 slm_logout(
                    SLM_HANDLE_INDEX slm_handle)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_logout64_windows(slm_handle);
                }
                return SlmRuntime.slm_logout32_windows(slm_handle);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_logout64_linux(slm_handle);
                }
                return SlmRuntime.slm_logout32_linux(slm_handle);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#6", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_keep_alive32_windows(
                    SLM_HANDLE_INDEX slm_handle);
        [DllImport(lib_name64, EntryPoint = "#6", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_keep_alive64_windows(
                    SLM_HANDLE_INDEX slm_handle);
        [DllImport(lib_name32, EntryPoint = "slm_keep_alive")]
        public static extern UInt32 slm_keep_alive32_linux(
                    SLM_HANDLE_INDEX slm_handle);
        [DllImport(lib_name64, EntryPoint = "slm_keep_alive")]
        public static extern UInt32 slm_keep_alive64_linux(
                    SLM_HANDLE_INDEX slm_handle);
        internal static UInt32 slm_keep_alive(
                    SLM_HANDLE_INDEX slm_handle)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_keep_alive64_windows(slm_handle);
                }
                return SlmRuntime.slm_keep_alive32_windows(slm_handle);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_keep_alive64_linux(slm_handle);
                }
                return SlmRuntime.slm_keep_alive32_linux(slm_handle);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="module_id"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#7", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_check_module32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 module_id);
        [DllImport(lib_name64, EntryPoint = "#7", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_check_module64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 module_id);
        [DllImport(lib_name32, EntryPoint = "slm_check_module")]
        public static extern UInt32 slm_check_module32_linux(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 module_id);
        [DllImport(lib_name64, EntryPoint = "slm_check_module")]
        public static extern UInt32 slm_check_module64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 module_id);
        internal static UInt32 slm_check_module(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 module_id)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_check_module64_windows(slm_handle, module_id);
                }
                return SlmRuntime.slm_check_module32_windows(slm_handle, module_id);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_check_module64_linux(slm_handle, module_id);
                }
                return SlmRuntime.slm_check_module32_linux(slm_handle, module_id);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="inbuffer"></param>
        /// <param name="outbuffer"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#8", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_encrypt32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
                    UInt32 len);
        [DllImport(lib_name64, EntryPoint = "#8", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_encrypt64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
                    UInt32 len);
        [DllImport(lib_name32, EntryPoint = "slm_encrypt")]
        public static extern UInt32 slm_encrypt32_linux(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
            [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
            UInt32 len);
        [DllImport(lib_name64, EntryPoint = "slm_encrypt")]
        public static extern UInt32 slm_encrypt64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
                    UInt32 len);
        internal static UInt32 slm_encrypt(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
                    UInt32 len)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_encrypt64_windows(slm_handle, inbuffer, outbuffer, len);
                }
                return SlmRuntime.slm_encrypt32_windows(slm_handle, inbuffer, outbuffer, len);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_encrypt64_linux(slm_handle, inbuffer, outbuffer, len);
                }
                return SlmRuntime.slm_encrypt32_linux(slm_handle, inbuffer, outbuffer, len);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="inbuffer"></param>
        /// <param name="outbuffer"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#9", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_decrypt32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
                    UInt32 len);
        [DllImport(lib_name64, EntryPoint = "#9", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_decrypt64_windows(
                   SLM_HANDLE_INDEX slm_handle,
                   [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
                   [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
                   UInt32 len);
        [DllImport(lib_name32, EntryPoint = "slm_decrypt")]
        public static extern UInt32 slm_decrypt32_linux(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
            [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
            UInt32 len);
        [DllImport(lib_name64, EntryPoint = "slm_decrypt")]
        public static extern UInt32 slm_decrypt64_linux(
                   SLM_HANDLE_INDEX slm_handle,
                   [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
                   [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
                   UInt32 len);
        internal static UInt32 slm_decrypt(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
                    UInt32 len)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_decrypt64_windows(slm_handle, inbuffer, outbuffer, len);
                }
                return SlmRuntime.slm_decrypt32_windows(slm_handle, inbuffer, outbuffer, len);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_decrypt64_linux(slm_handle, inbuffer, outbuffer, len);
                }
                return SlmRuntime.slm_decrypt32_linux(slm_handle, inbuffer, outbuffer, len);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="type"></param>
        /// <param name="pmem_size"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#10", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_getsize32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    LIC_USER_DATA_TYPE type,
                    ref UInt32 pmem_size);
        [DllImport(lib_name64, EntryPoint = "#10", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_getsize64_windows(
                   SLM_HANDLE_INDEX slm_handle,
                   LIC_USER_DATA_TYPE type,
                   ref UInt32 pmem_size);
        [DllImport(lib_name32, EntryPoint = "slm_user_data_getsize")]
        public static extern UInt32 slm_user_data_getsize32_linux(
            SLM_HANDLE_INDEX slm_handle,
            LIC_USER_DATA_TYPE type,
            ref UInt32 pmem_size);
        [DllImport(lib_name64, EntryPoint = "slm_user_data_getsize")]
        public static extern UInt32 slm_user_data_getsize64_linux(
                   SLM_HANDLE_INDEX slm_handle,
                   LIC_USER_DATA_TYPE type,
                   ref UInt32 pmem_size);
        internal static UInt32 slm_user_data_getsize(
                    SLM_HANDLE_INDEX slm_handle,
                    LIC_USER_DATA_TYPE type,
                    ref UInt32 pmem_size)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_user_data_getsize64_windows(slm_handle, type, ref pmem_size);
                }
                return SlmRuntime.slm_user_data_getsize32_windows(slm_handle, type, ref pmem_size);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_user_data_getsize64_linux(slm_handle, type, ref pmem_size);
                }
                return SlmRuntime.slm_user_data_getsize32_linux(slm_handle, type, ref pmem_size);
            }
        }
        /// <summary>
        /// 读许可数据，可以读取RW和ROM
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="type"></param>
        /// <param name="readbuf"></param>
        /// <param name="offset"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#11", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_read32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    LIC_USER_DATA_TYPE type,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
                    UInt32 offset,
                    UInt32 len);
        [DllImport(lib_name64, EntryPoint = "#11", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_read64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    LIC_USER_DATA_TYPE type,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
                    UInt32 offset,
                    UInt32 len);
        [DllImport(lib_name32, EntryPoint = "slm_user_data_read")]
        public static extern UInt32 slm_user_data_read32_linux(
            SLM_HANDLE_INDEX slm_handle,
            LIC_USER_DATA_TYPE type,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
            UInt32 offset,
            UInt32 len);
        [DllImport(lib_name64, EntryPoint = "slm_user_data_read")]
        public static extern UInt32 slm_user_data_read64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    LIC_USER_DATA_TYPE type,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
                    UInt32 offset,
                    UInt32 len);
        internal static UInt32 slm_user_data_read(
                    SLM_HANDLE_INDEX slm_handle,
                    LIC_USER_DATA_TYPE type,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
                    UInt32 offset,
                    UInt32 len)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_user_data_read64_windows(slm_handle, type, readbuf, offset, len);
                }
                return SlmRuntime.slm_user_data_read32_windows(slm_handle, type, readbuf, offset, len);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_user_data_read64_linux(slm_handle, type, readbuf, offset, len);
                }
                return SlmRuntime.slm_user_data_read32_linux(slm_handle, type, readbuf, offset, len);
            }
        }
        /// <summary>
        /// 写许可的读写数据区 ,数据区操作之前请先确认内存区的大小，可以使用slm_user_data_getsize获得
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="writebuf"></param>
        /// <param name="offset"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#12", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_write32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuf,
                    UInt32 offset,
                    UInt32 len);
        [DllImport(lib_name64, EntryPoint = "#12", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_write64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuf,
                    UInt32 offset,
                    UInt32 len);
        [DllImport(lib_name32, EntryPoint = "slm_user_data_write")]
        public static extern UInt32 slm_user_data_write32_linux(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuf,
            UInt32 offset,
            UInt32 len);
        [DllImport(lib_name64, EntryPoint = "slm_user_data_write")]
        public static extern UInt32 slm_user_data_write64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuf,
                    UInt32 offset,
                    UInt32 len);
        internal static UInt32 slm_user_data_write(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuf,
                    UInt32 offset,
                    UInt32 len)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_user_data_write64_windows(slm_handle, writebuf, offset, len);
                }
                return SlmRuntime.slm_user_data_write32_windows(slm_handle, writebuf, offset, len);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_user_data_write64_linux(slm_handle, writebuf, offset, len);
                }
                return SlmRuntime.slm_user_data_write32_linux(slm_handle, writebuf, offset, len);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="info_type"></param>
        /// <param name="format"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#13", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_info32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    INFO_TYPE info_type,
                    INFO_FORMAT_TYPE format,
                    ref IntPtr result);
        [DllImport(lib_name64, EntryPoint = "#13", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_info64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    INFO_TYPE info_type,
                    INFO_FORMAT_TYPE format,
                    ref IntPtr result);
        [DllImport(lib_name32, EntryPoint = "slm_get_info")]
        public static extern UInt32 slm_get_info32_linux(
            SLM_HANDLE_INDEX slm_handle,
            INFO_TYPE info_type,
            INFO_FORMAT_TYPE format,
            ref IntPtr result);
        [DllImport(lib_name64, EntryPoint = "slm_get_info")]
        public static extern UInt32 slm_get_info64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    INFO_TYPE info_type,
                    INFO_FORMAT_TYPE format,
                    ref IntPtr result);
        internal static UInt32 slm_get_info(
                    SLM_HANDLE_INDEX slm_handle,
                    INFO_TYPE info_type,
                    INFO_FORMAT_TYPE format,
                    ref IntPtr result)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_info64_windows(slm_handle, info_type, format, ref result);
                }
                return SlmRuntime.slm_get_info32_windows(slm_handle, info_type, format, ref result);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_info64_linux(slm_handle, info_type, format, ref result);
                }
                return SlmRuntime.slm_get_info32_linux(slm_handle, info_type, format, ref result);
            }
        }
        /// <summary>
        /// 执行锁内算法
        /// </summary>
        /// <param name="slm_handle">许可句柄值</param>
        /// <param name="exfname">锁内执行文件名</param>
        /// <param name="inbuf">输入缓冲区</param>
        /// <param name="insize">输入长度</param>
        /// <param name="poutbuf">输出缓存区</param>
        /// <param name="outsize">输出缓存长度</param>
        /// <param name="pretsize">实际返回缓存长度</param>
        /// <returns>成功返回SS_OK，失败返回相应的错误码</returns>
        [DllImport(lib_name32, EntryPoint = "#14", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_execute_static32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPTStr)] string exfname,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
                    UInt32 insize,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
                    UInt32 outsize,
                    ref UInt32 pretsize);
        [DllImport(lib_name64, EntryPoint = "#14", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_execute_static64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPTStr)] string exfname,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
                    UInt32 insize,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
                    UInt32 outsize,
                    ref UInt32 pretsize);
        [DllImport(lib_name32, EntryPoint = "slm_execute_static")]
        public static extern UInt32 slm_execute_static32_linux(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPTStr)] string exfname,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
            UInt32 insize,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
            UInt32 outsize,
            ref UInt32 pretsize);
        [DllImport(lib_name64, EntryPoint = "slm_execute_static")]
        public static extern UInt32 slm_execute_static64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPTStr)] string exfname,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
                    UInt32 insize,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
                    UInt32 outsize,
                    ref UInt32 pretsize);
        internal static UInt32 slm_execute_static(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPTStr)] string exfname,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
            UInt32 insize,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
            UInt32 outsize,
            ref UInt32 pretsize)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_execute_static64_windows(slm_handle, exfname, inbuf, insize, poutbuf, outsize, ref pretsize);
                }
                return SlmRuntime.slm_execute_static32_windows(slm_handle, exfname, inbuf, insize, poutbuf, outsize, ref pretsize);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_execute_static64_linux(slm_handle, exfname, inbuf, insize, poutbuf, outsize, ref pretsize);
                }
                return SlmRuntime.slm_execute_static32_linux(slm_handle, exfname, inbuf, insize, poutbuf, outsize, ref pretsize);
            }
        }
        /// <summary>
        /// 许可动态执行代码，由开发商API gen_dynamic_code生成
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="exf_buffer"></param>
        /// <param name="exf_size"></param>
        /// <param name="inbuf"></param>
        /// <param name="insize"></param>
        /// <param name="poutbuf"></param>
        /// <param name="outsize"></param>
        /// <param name="pretsize"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#15", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_execute_dynamic32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] exf_buffer,
                    UInt32 exf_size,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
                    UInt32 insize,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
                    UInt32 outsize,
                    ref UInt32 pretsize);
        [DllImport(lib_name64, EntryPoint = "#15", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_execute_dynamic64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] exf_buffer,
                    UInt32 exf_size,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
                    UInt32 insize,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
                    UInt32 outsize,
                    ref UInt32 pretsize);
        [DllImport(lib_name32, EntryPoint = "slm_execute_dynamic")]
        public static extern UInt32 slm_execute_dynamic32_linux(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] exf_buffer,
            UInt32 exf_size,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
            UInt32 insize,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
            UInt32 outsize,
            ref UInt32 pretsize);
        [DllImport(lib_name64, EntryPoint = "slm_execute_dynamic")]
        public static extern UInt32 slm_execute_dynamic64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] exf_buffer,
                    UInt32 exf_size,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
                    UInt32 insize,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
                    UInt32 outsize,
                    ref UInt32 pretsize);
        internal static UInt32 slm_execute_dynamic(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] exf_buffer,
                    UInt32 exf_size,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
                    UInt32 insize,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
                    UInt32 outsize,
                    ref UInt32 pretsize)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_execute_dynamic64_windows(slm_handle, exf_buffer, exf_size, inbuf, insize, poutbuf, outsize, ref pretsize);
                }
                return SlmRuntime.slm_execute_dynamic32_windows(slm_handle, exf_buffer, exf_size, inbuf, insize, poutbuf, outsize, ref pretsize);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_execute_dynamic64_linux(slm_handle, exf_buffer, exf_size, inbuf, insize, poutbuf, outsize, ref pretsize);
                }
                return SlmRuntime.slm_execute_dynamic32_linux(slm_handle, exf_buffer, exf_size, inbuf, insize, poutbuf, outsize, ref pretsize);
            }
        }
        /// <summary>
        /// SS内存托管内存申请
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="size"></param>
        /// <param name="mem_id"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#17", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_alloc32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 size,
                    ref UInt32 mem_id);
        [DllImport(lib_name64, EntryPoint = "#17", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_alloc64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 size,
                    ref UInt32 mem_id);
        [DllImport(lib_name32, EntryPoint = "slm_mem_alloc")]
        public static extern UInt32 slm_mem_alloc32_linux(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 size,
            ref UInt32 mem_id);
        [DllImport(lib_name64, EntryPoint = "slm_mem_alloc")]
        public static extern UInt32 slm_mem_alloc64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 size,
                    ref UInt32 mem_id);
        internal static UInt32 slm_mem_alloc(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 size,
                    ref UInt32 mem_id)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_mem_alloc64_windows(slm_handle, size, ref mem_id);
                }
                return SlmRuntime.slm_mem_alloc32_windows(slm_handle, size, ref mem_id);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_mem_alloc64_linux(slm_handle, size, ref mem_id);
                }
                return SlmRuntime.slm_mem_alloc32_linux(slm_handle, size, ref mem_id);
            }
        }
        /// <summary>
        /// 释放托管内存
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="mem_id"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#18", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_free32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id);
        [DllImport(lib_name64, EntryPoint = "#18", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_free64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id);
        [DllImport(lib_name32, EntryPoint = "slm_mem_free")]
        public static extern UInt32 slm_mem_free32_linux(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id);
        [DllImport(lib_name64, EntryPoint = "slm_mem_free")]
        public static extern UInt32 slm_mem_free64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id);
        internal static UInt32 slm_mem_free(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_mem_free64_windows(slm_handle, mem_id);
                }
                return SlmRuntime.slm_mem_free32_windows(slm_handle, mem_id);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_mem_free64_linux(slm_handle, mem_id);
                }
                return SlmRuntime.slm_mem_free32_linux(slm_handle, mem_id);
            }
        }
        /// <summary>
        /// SS内存托管读
        /// </summary>
        /// <param name="slm_handle">许可句柄值</param>
        /// <param name="mem_id">托管内存id</param>
        /// <param name="offset">偏移</param>
        /// <param name="len">长度</param>
        /// <param name="readbuff">缓存</param>
        /// <param name="readlen">返回实际读的长度</param>
        /// <returns>成功返回SS_OK，失败返回相应的错误码</returns>
        [DllImport(lib_name32, EntryPoint = "#19", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_read32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id,
                    UInt32 offset,
                    UInt32 len,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] readbuff,
                    ref UInt32 readlen);
        [DllImport(lib_name64, EntryPoint = "#19", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_read64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id,
                    UInt32 offset,
                    UInt32 len,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] readbuff,
                    ref UInt32 readlen);
        [DllImport(lib_name32, EntryPoint = "slm_mem_read")]
        public static extern UInt32 slm_mem_read32_linux(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id,
            UInt32 offset,
            UInt32 len,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] readbuff,
            ref UInt32 readlen);
        [DllImport(lib_name64, EntryPoint = "slm_mem_read")]
        public static extern UInt32 slm_mem_read64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id,
                    UInt32 offset,
                    UInt32 len,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] readbuff,
                    ref UInt32 readlen);
        internal static UInt32 slm_mem_read(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id,
                    UInt32 offset,
                    UInt32 len,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] readbuff,
                    ref UInt32 readlen)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_mem_read64_windows(slm_handle, mem_id, offset, len, readbuff, ref readlen);
                }
                return SlmRuntime.slm_mem_read32_windows(slm_handle, mem_id, offset, len, readbuff, ref readlen);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_mem_read64_linux(slm_handle, mem_id, offset, len, readbuff, ref readlen);
                }
                return SlmRuntime.slm_mem_read32_linux(slm_handle, mem_id, offset, len, readbuff, ref readlen);
            }
        }
        /// <summary>
        /// SS内存托管内存写入
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="mem_id"></param>
        /// <param name="offset"></param>
        /// <param name="len"></param>
        /// <param name="writebuff"></param>
        /// <param name="numberofbyteswritten"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#20", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_write32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id,
                    UInt32 offset,
                    UInt32 len,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuff,
                    ref UInt32 numberofbyteswritten);
        [DllImport(lib_name64, EntryPoint = "#20", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_write64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id,
                    UInt32 offset,
                    UInt32 len,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuff,
                    ref UInt32 numberofbyteswritten);
        [DllImport(lib_name32, EntryPoint = "slm_mem_write")]
        public static extern UInt32 slm_mem_write32_linux(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id,
            UInt32 offset,
            UInt32 len,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuff,
            ref UInt32 numberofbyteswritten);
        [DllImport(lib_name64, EntryPoint = "slm_mem_write")]
        public static extern UInt32 slm_mem_write64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id,
                    UInt32 offset,
                    UInt32 len,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuff,
                    ref UInt32 numberofbyteswritten);
        internal static UInt32 slm_mem_write(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 mem_id,
                    UInt32 offset,
                    UInt32 len,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] readbuff,
                    ref UInt32 readlen)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_mem_write64_windows(slm_handle, mem_id, offset, len, readbuff, ref readlen);
                }
                return SlmRuntime.slm_mem_write32_windows(slm_handle, mem_id, offset, len, readbuff, ref readlen);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_mem_write64_linux(slm_handle, mem_id, offset, len, readbuff, ref readlen);
                }
                return SlmRuntime.slm_mem_write32_linux(slm_handle, mem_id, offset, len, readbuff, ref readlen);
            }
        }
        /// <summary>
        /// 检测是否正在调试
        /// </summary>
        /// <param name="auth">auth 验证数据(目前填IntPtr.Zero即可）</param>
        /// <returns>SS_UINT32错误码, 返回SS_OK代表未调试</returns>
        [DllImport(lib_name32, EntryPoint = "#21", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_is_debug32_windows(
                    IntPtr auth);
        [DllImport(lib_name64, EntryPoint = "#21", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_is_debug64_windows(
                    IntPtr auth);
        [DllImport(lib_name32, EntryPoint = "slm_is_debug")]
        public static extern UInt32 slm_is_debug32_linux(
            IntPtr auth);
        [DllImport(lib_name64, EntryPoint = "slm_is_debug")]
        public static extern UInt32 slm_is_debug64_linux(
                    IntPtr auth);
        internal static UInt32 slm_is_debug(
                    IntPtr auth)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_is_debug64_windows(auth);
                }
                return SlmRuntime.slm_is_debug32_windows(auth);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_is_debug64_linux(auth);
                }
                return SlmRuntime.slm_is_debug32_linux(auth);
            }
        }
        /// <summary>
        /// 获取锁的设备证书
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="device_cert"></param>
        /// <param name="buff_size"></param>
        /// <param name="return_size"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#22", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_device_cert32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] device_cert,
                    UInt32 buff_size,
                    ref UInt32 return_size);
        [DllImport(lib_name64, EntryPoint = "#22", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_device_cert64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] device_cert,
                    UInt32 buff_size,
                    ref UInt32 return_size);
        [DllImport(lib_name32, EntryPoint = "slm_get_device_cert")]
        public static extern UInt32 slm_get_device_cert32_linux(
            SLM_HANDLE_INDEX slm_handle,
            [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] device_cert,
            UInt32 buff_size,
            ref UInt32 return_size);
        [DllImport(lib_name64, EntryPoint = "slm_get_device_cert")]
        public static extern UInt32 slm_get_device_cert64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] device_cert,
                    UInt32 buff_size,
                    ref UInt32 return_size);
        internal static UInt32 slm_get_device_cert(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] device_cert,
                    UInt32 buff_size,
                    ref UInt32 return_size)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_device_cert64_windows(slm_handle, device_cert, buff_size, ref return_size);
                }
                return SlmRuntime.slm_get_device_cert32_windows(slm_handle, device_cert, buff_size, ref return_size);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_device_cert64_linux(slm_handle, device_cert, buff_size, ref return_size);
                }
                return SlmRuntime.slm_get_device_cert32_linux(slm_handle, device_cert, buff_size, ref return_size);
            }
        }
        /// <summary>
        /// 设备正版验证
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="verify_data"></param>
        /// <param name="verify_data_size"></param>
        /// <param name="signature"></param>
        /// <param name="signature_buf_size"></param>
        /// <param name="signature_size"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#23", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_sign_by_device32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] verify_data,
                    UInt32 verify_data_size,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                    UInt32 signature_buf_size,
                    ref UInt32 signature_size);
        [DllImport(lib_name64, EntryPoint = "#23", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_sign_by_device64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] verify_data,
                    UInt32 verify_data_size,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                    UInt32 signature_buf_size,
                    ref UInt32 signature_size);
        [DllImport(lib_name32, EntryPoint = "slm_sign_by_device")]
        public static extern UInt32 slm_sign_by_device32_linux(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] verify_data,
            UInt32 verify_data_size,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 signature_buf_size,
            ref UInt32 signature_size);
        [DllImport(lib_name64, EntryPoint = "slm_sign_by_device")]
        public static extern UInt32 slm_sign_by_device64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] verify_data,
                    UInt32 verify_data_size,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                    UInt32 signature_buf_size,
                    ref UInt32 signature_size);
        internal static UInt32 slm_sign_by_device(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] verify_data,
                    UInt32 verify_data_size,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                    UInt32 signature_buf_size,
                    ref UInt32 signature_size)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_sign_by_device64_windows(slm_handle, verify_data, verify_data_size, signature, signature_buf_size, ref signature_size);
                }
                return SlmRuntime.slm_sign_by_device32_windows(slm_handle, verify_data, verify_data_size, signature, signature_buf_size, ref signature_size);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_sign_by_device64_linux(slm_handle, verify_data, verify_data_size, signature, signature_buf_size, ref signature_size);
                }
                return SlmRuntime.slm_sign_by_device32_linux(slm_handle, verify_data, verify_data_size, signature, signature_buf_size, ref signature_size);
            }
        }
        /// <summary>
        /// 获取时间修复数据，用于生成时钟校准请求
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="rand"></param>
        /// <param name="lock_time"></param>
        /// <param name="pc_time"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#24", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_adjust_time_request32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] rand,
                    ref UInt32 lock_time,
                    ref UInt32 pc_time
                    );
        [DllImport(lib_name64, EntryPoint = "#24", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_adjust_time_request64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] rand,
                    ref UInt32 lock_time,
                    ref UInt32 pc_time
                    );
        [DllImport(lib_name32, EntryPoint = "slm_adjust_time_request")]
        public static extern UInt32 slm_adjust_time_request32_linux(
            SLM_HANDLE_INDEX slm_handle,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] rand,
            ref UInt32 lock_time,
            ref UInt32 pc_time
            );
        [DllImport(lib_name64, EntryPoint = "slm_adjust_time_request")]
        public static extern UInt32 slm_adjust_time_request64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] rand,
                    ref UInt32 lock_time,
                    ref UInt32 pc_time
                    );
        internal static UInt32 slm_adjust_time_request(
                    SLM_HANDLE_INDEX slm_handle,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] rand,
                    ref UInt32 lock_time,
                    ref UInt32 pc_time
                    )
        {

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_adjust_time_request64_windows(slm_handle, rand, ref lock_time, ref pc_time);
                }
                return SlmRuntime.slm_adjust_time_request32_windows(slm_handle, rand, ref lock_time, ref pc_time);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_adjust_time_request64_linux(slm_handle, rand, ref lock_time, ref pc_time);
                }
                return SlmRuntime.slm_adjust_time_request32_linux(slm_handle, rand, ref lock_time, ref pc_time);
            }
        }
        /// <summary>
        /// 闪烁指示灯
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="led_ctrl"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#25", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_led_control32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    ref ST_LED_CONTROL led_ctrl);
        [DllImport(lib_name64, EntryPoint = "#25", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_led_control64_windows(
                   SLM_HANDLE_INDEX slm_handle,
                   ref ST_LED_CONTROL led_ctrl);
        [DllImport(lib_name32, EntryPoint = "slm_led_control")]
        public static extern UInt32 slm_led_control32_linux(
            SLM_HANDLE_INDEX slm_handle,
            ref ST_LED_CONTROL led_ctrl);
        [DllImport(lib_name64, EntryPoint = "slm_led_control")]
        public static extern UInt32 slm_led_control64_linux(
                   SLM_HANDLE_INDEX slm_handle,
                   ref ST_LED_CONTROL led_ctrl);
        internal static UInt32 slm_led_control(
                    SLM_HANDLE_INDEX slm_handle,
                    ref ST_LED_CONTROL led_ctrl)
        {

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_led_control64_windows(slm_handle, ref led_ctrl);
                }
                return SlmRuntime.slm_led_control32_windows(slm_handle, ref led_ctrl);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_led_control64_linux(slm_handle, ref led_ctrl);
                }
                return SlmRuntime.slm_led_control32_linux(slm_handle, ref led_ctrl);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="api_version"></param>
        /// <param name="ss_version"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#26", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_version32_windows(
                    ref UInt32 api_version,
                    ref UInt32 ss_version);
        [DllImport(lib_name64, EntryPoint = "#26", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_version64_windows(
                    ref UInt32 api_version,
                    ref UInt32 ss_version);
        [DllImport(lib_name32, EntryPoint = "slm_get_version")]
        public static extern UInt32 slm_get_version32_linux(
            ref UInt32 api_version,
            ref UInt32 ss_version);
        [DllImport(lib_name64, EntryPoint = "slm_get_version")]
        public static extern UInt32 slm_get_version64_linux(
                    ref UInt32 api_version,
                    ref UInt32 ss_version);
        internal static UInt32 slm_get_version(
                    ref UInt32 api_version,
                    ref UInt32 ss_version)
        {

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_version64_windows(ref api_version, ref ss_version);
                }
                return SlmRuntime.slm_get_version32_windows(ref api_version, ref ss_version);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_version64_linux(ref api_version, ref ss_version);
                }
                return SlmRuntime.slm_get_version32_linux(ref api_version, ref ss_version);
            }
        }
        /// <summary>
        /// 升级许可
        /// </summary>
        /// <param name="d2c_pkg">许可D2C数据</param>
        /// <param name="error_msg">错误信息（json）</param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#27", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_update32_windows(
                    [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
                    ref IntPtr error_msg);
        [DllImport(lib_name64, EntryPoint = "#27", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_update64_windows(
                    [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
                    ref IntPtr error_msg);
        [DllImport(lib_name32, EntryPoint = "slm_update")]
        public static extern UInt32 slm_update32_linux(
            [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
            ref IntPtr error_msg);
        [DllImport(lib_name64, EntryPoint = "slm_update")]
        public static extern UInt32 slm_update64_linux(
                    [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
                    ref IntPtr error_msg);
        internal static UInt32 slm_update(
                    [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
                    ref IntPtr error_msg)
        {

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_update64_windows(d2c_pkg, ref error_msg);
                }
                return SlmRuntime.slm_update32_windows(d2c_pkg, ref error_msg);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_update64_linux(d2c_pkg, ref error_msg);
                }
                return SlmRuntime.slm_update32_linux(d2c_pkg, ref error_msg);
            }
        }
        /// <summary>
        ///  将D2C包进行升级
        /// </summary>
        /// <param name="lock_sn"></param>
        /// <param name="d2c_pkg"></param>
        /// <param name="error_msg"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#28", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_update_ex32_windows(
                     [In, MarshalAs(UnmanagedType.LPArray)] byte[] lock_sn,
                    [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
                    ref IntPtr error_msg);
        [DllImport(lib_name64, EntryPoint = "#28", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_update_ex64_windows(
                     [In, MarshalAs(UnmanagedType.LPArray)] byte[] lock_sn,
                    [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
                    ref IntPtr error_msg);
        [DllImport(lib_name32, EntryPoint = "slm_update_ex")]
        public static extern UInt32 slm_update_ex32_linux(
             [In, MarshalAs(UnmanagedType.LPArray)] byte[] lock_sn,
            [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
            ref IntPtr error_msg);
        [DllImport(lib_name64, EntryPoint = "slm_update_ex")]
        public static extern UInt32 slm_update_ex64_linux(
                     [In, MarshalAs(UnmanagedType.LPArray)] byte[] lock_sn,
                    [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
                    ref IntPtr error_msg);
        internal static UInt32 slm_update_ex(
                     [In, MarshalAs(UnmanagedType.LPArray)] byte[] lock_sn,
                    [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
                    ref IntPtr error_msg)
        {

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_update_ex64_windows(lock_sn, d2c_pkg, ref error_msg);
                }
                return SlmRuntime.slm_update_ex32_windows(lock_sn, d2c_pkg, ref error_msg);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_update_ex64_linux(lock_sn, d2c_pkg, ref error_msg);
                }
                return SlmRuntime.slm_update_ex32_linux(lock_sn, d2c_pkg, ref error_msg);
            }
        }

        /// <summary>
        ///  枚举本地锁信息
        /// </summary>
        /// <param name="device_info"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#29", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_enum_device32_windows(
                   ref IntPtr device_info);
        [DllImport(lib_name64, EntryPoint = "#29", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_enum_device64_windows(
                  ref IntPtr device_info);
        [DllImport(lib_name32, EntryPoint = "slm_enum_device")]
        public static extern UInt32 slm_enum_device32_linux(
           ref IntPtr device_info);
        [DllImport(lib_name64, EntryPoint = "slm_enum_device")]
        public static extern UInt32 slm_enum_device64_linux(
                  ref IntPtr device_info);
        internal static UInt32 slm_enum_device(
                   ref IntPtr device_info)
        {

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_enum_device64_windows(ref device_info);
                }
                return SlmRuntime.slm_enum_device32_windows(ref device_info);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_enum_device64_linux(ref device_info);
                }
                return SlmRuntime.slm_enum_device32_linux(ref device_info);
            }
        }
        /// <summary>
        ///   
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#30", CallingConvention = CallingConvention.StdCall)]
        public static extern void slm_free32_windows(IntPtr buffer);
        [DllImport(lib_name64, EntryPoint = "#30", CallingConvention = CallingConvention.StdCall)]
        public static extern void slm_free64_windows(IntPtr buffer);
        [DllImport(lib_name32, EntryPoint = "slm_free")]
        public static extern void slm_free32_linux(IntPtr buffer);
        [DllImport(lib_name64, EntryPoint = "slm_free")]
        public static extern void slm_free64_linux(IntPtr buffer);
        internal static void slm_free(IntPtr buffer)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                    SlmRuntime.slm_free64_windows(buffer);
                else
                    SlmRuntime.slm_free32_windows(buffer);
            }
            else
            {
                if (SlmRuntime.Is64)
                    SlmRuntime.slm_free64_linux(buffer);
                else
                    SlmRuntime.slm_free32_linux(buffer);
            }
        }
        /// <summary>
        ///   获取API对应的开发商ID
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#31", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_developer_id32_windows(
                   [Out, MarshalAs(UnmanagedType.LPArray)] byte[] buffer);
        [DllImport(lib_name64, EntryPoint = "#31", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_developer_id64_windows(
                   [Out, MarshalAs(UnmanagedType.LPArray)] byte[] buffer);
        [DllImport(lib_name32, EntryPoint = "slm_get_developer_id")]
        public static extern UInt32 slm_get_developer_id32_linux(
           [Out, MarshalAs(UnmanagedType.LPArray)] byte[] buffer);
        [DllImport(lib_name64, EntryPoint = "slm_get_developer_id")]
        public static extern UInt32 slm_get_developer_id64_linux(
                   [Out, MarshalAs(UnmanagedType.LPArray)] byte[] buffer);
        internal static UInt32 slm_get_developer_id(
                   [Out, MarshalAs(UnmanagedType.LPArray)] byte[] buffer)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_developer_id64_windows(buffer);
                }
                return SlmRuntime.slm_get_developer_id32_windows(buffer);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_developer_id64_linux(buffer);
                }
                return SlmRuntime.slm_get_developer_id32_linux(buffer);
            }
        }
        /// <summary>
        /// 通过错误码获得错误信息
        /// </summary>
        /// <param name="error_code"></param>
        /// <param name="language_id"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#32", CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr slm_error_format32_windows(
           UInt32 error_code,
           UInt32 language_id
            );
        [DllImport(lib_name64, EntryPoint = "#32", CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr slm_error_format64_windows(
           UInt32 error_code,
           UInt32 language_id
            );
        [DllImport(lib_name32, EntryPoint = "slm_error_format")]
        public static extern IntPtr slm_error_format32_linux(
        UInt32 error_code,
        UInt32 language_id
        );
        [DllImport(lib_name64, EntryPoint = "slm_error_format")]
        public static extern IntPtr slm_error_format64_linux(
           UInt32 error_code,
           UInt32 language_id
            );
        internal static IntPtr slm_error_format(
                   UInt32 error_code,
                   UInt32 language_id
                    )
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_error_format64_windows(error_code, language_id);
                }
                return SlmRuntime.slm_error_format32_windows(error_code, language_id);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_error_format64_linux(error_code, language_id);
                }
                return SlmRuntime.slm_error_format32_linux(error_code, language_id);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#33", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_cleanup32_windows();
        [DllImport(lib_name64, EntryPoint = "#33", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_cleanup64_windows();

        [DllImport(lib_name32, EntryPoint = "slm_cleanup")]
        public static extern UInt32 slm_cleanup32_linux();
        [DllImport(lib_name64, EntryPoint = "slm_cleanup")]
        public static extern UInt32 slm_cleanup64_linux();

        internal static UInt32 slm_cleanup()
        {

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_cleanup64_windows();
                }
                return SlmRuntime.slm_cleanup32_windows();
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_cleanup64_linux();
                }
                return SlmRuntime.slm_cleanup32_linux();
            }
        }


        /// <summary>
        /// 碎片代码执行（开发者不必关心）
        /// </summary>
        /// <param name="slm_handle"></param> 
        /// <param name="snippet_code"></param>
        /// <param name="code_size"></param>
        /// <param name="input"></param>
        /// <param name="input_size"></param>
        /// <param name="output"></param>
        /// <param name="outbuf_size"></param>
        /// <param name="output_size"></param> 
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#35", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_snippet_execute32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] d2c_pkg,
                    UInt32 code_size,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] input,
                    UInt32 input_size,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] output,
                    UInt32 outbuf_size,
                    ref UInt32 language_id);
        [DllImport(lib_name64, EntryPoint = "#35", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_snippet_execute64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] d2c_pkg,
                    UInt32 code_size,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] input,
                    UInt32 input_size,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] output,
                    UInt32 outbuf_size,
                    ref UInt32 language_id);
        [DllImport(lib_name32, EntryPoint = "slm_snippet_execute")]
        public static extern UInt32 slm_snippet_execute32_linux(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] d2c_pkg,
            UInt32 code_size,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] input,
            UInt32 input_size,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] output,
            UInt32 outbuf_size,
            ref UInt32 language_id);
        [DllImport(lib_name64, EntryPoint = "slm_snippet_execute")]
        public static extern UInt32 slm_snippet_execute64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] d2c_pkg,
                    UInt32 code_size,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] input,
                    UInt32 input_size,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] output,
                    UInt32 outbuf_size,
                    ref UInt32 language_id);
        internal static UInt32 slm_snippet_execute(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] d2c_pkg,
                    UInt32 code_size,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] input,
                    UInt32 input_size,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] output,
                    UInt32 outbuf_size,
                    ref UInt32 language_id)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_snippet_execute64_windows(slm_handle, d2c_pkg, code_size, input, input_size, output, outbuf_size, ref language_id);
                }
                return SlmRuntime.slm_snippet_execute32_windows(slm_handle, d2c_pkg, code_size, input, input_size, output, outbuf_size, ref language_id);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_snippet_execute64_linux(slm_handle, d2c_pkg, code_size, input, input_size, output, outbuf_size, ref language_id);
                }
                return SlmRuntime.slm_snippet_execute32_linux(slm_handle, d2c_pkg, code_size, input, input_size, output, outbuf_size, ref language_id);
            }
        }
        /// <summary>
        /// 获得指定许可的公开区数据区大小，需要登录0号许可
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="license_id"></param>
        /// <param name="pmem_size"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#36", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_pub_data_getsize32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 license_id,
                    ref UInt32 pmem_size);
        [DllImport(lib_name64, EntryPoint = "#36", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_pub_data_getsize64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 license_id,
                    ref UInt32 pmem_size);
        [DllImport(lib_name32, EntryPoint = "slm_pub_data_getsize")]
        public static extern UInt32 slm_pub_data_getsize32_linux(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 license_id,
            ref UInt32 pmem_size);
        [DllImport(lib_name64, EntryPoint = "slm_pub_data_getsize")]
        public static extern UInt32 slm_pub_data_getsize64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 license_id,
                    ref UInt32 pmem_size);
        internal static UInt32 slm_pub_data_getsize(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 license_id,
                    ref UInt32 pmem_size)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_pub_data_getsize64_windows(slm_handle, license_id, ref pmem_size);
                }
                return SlmRuntime.slm_pub_data_getsize32_windows(slm_handle, license_id, ref pmem_size);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_pub_data_getsize64_linux(slm_handle, license_id, ref pmem_size);
                }
                return SlmRuntime.slm_pub_data_getsize32_linux(slm_handle, license_id, ref pmem_size);
            }
        }
        /// <summary>
        /// 获得指定许可的公开区数据区大小，需要登录0号许可
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="license_id"></param>
        /// <param name="readbuf"></param>
        /// <param name="offset"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#37", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_pub_data_read32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 license_id,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
                    UInt32 offset,
                    UInt32 len);
        [DllImport(lib_name64, EntryPoint = "#37", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_pub_data_read64_windows(
                   SLM_HANDLE_INDEX slm_handle,
                   UInt32 license_id,
                   [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
                   UInt32 offset,
                   UInt32 len);
        [DllImport(lib_name32, EntryPoint = "slm_pub_data_read")]
        public static extern UInt32 slm_pub_data_read32_linux(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 license_id,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
            UInt32 offset,
            UInt32 len);
        [DllImport(lib_name64, EntryPoint = "slm_pub_data_read")]
        public static extern UInt32 slm_pub_data_read64_linux(
                   SLM_HANDLE_INDEX slm_handle,
                   UInt32 license_id,
                   [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
                   UInt32 offset,
                   UInt32 len);
        internal static UInt32 slm_pub_data_read(
                    SLM_HANDLE_INDEX slm_handle,
                    UInt32 license_id,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
                    UInt32 offset,
                    UInt32 len)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_pub_data_read64_windows(slm_handle, license_id, readbuf, offset, len);
                }
                return SlmRuntime.slm_pub_data_read32_windows(slm_handle, license_id, readbuf, offset, len);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_pub_data_read64_linux(slm_handle, license_id, readbuf, offset, len);
                }
                return SlmRuntime.slm_pub_data_read32_linux(slm_handle, license_id, readbuf, offset, len);
            }
        }
        /// <summary>
        /// 锁内短码升级
        /// </summary>
        /// <param name="lock_sn"></param>
        /// <param name="inside_file"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#38", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_d2c_update_inside32_windows(
                    [In, MarshalAs(UnmanagedType.LPStr)] string lock_sn,
                    [In, MarshalAs(UnmanagedType.LPStr)] string inside_file);
        [DllImport(lib_name64, EntryPoint = "#38", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_d2c_update_inside64_windows(
                    [In, MarshalAs(UnmanagedType.LPStr)] string lock_sn,
                    [In, MarshalAs(UnmanagedType.LPStr)] string inside_file);
        [DllImport(lib_name32, EntryPoint = "slm_d2c_update_inside")]
        public static extern UInt32 slm_d2c_update_inside32_linux(
            [In, MarshalAs(UnmanagedType.LPStr)] string lock_sn,
            [In, MarshalAs(UnmanagedType.LPStr)] string inside_file);
        [DllImport(lib_name64, EntryPoint = "slm_d2c_update_inside")]
        public static extern UInt32 slm_d2c_update_inside64_linux(
                    [In, MarshalAs(UnmanagedType.LPStr)] string lock_sn,
                    [In, MarshalAs(UnmanagedType.LPStr)] string inside_file);
        internal static UInt32 slm_d2c_update_inside(
                    [In, MarshalAs(UnmanagedType.LPStr)] string lock_sn,
                    [In, MarshalAs(UnmanagedType.LPStr)] string inside_file)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_d2c_update_inside64_windows(lock_sn, inside_file);
                }
                return SlmRuntime.slm_d2c_update_inside32_windows(lock_sn, inside_file);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_d2c_update_inside64_linux(lock_sn, inside_file);
                }
                return SlmRuntime.slm_d2c_update_inside32_linux(lock_sn, inside_file);
            }
        }
        /// <summary>
        /// 枚举指定设备下所有许可ID
        /// </summary>
        /// <param name="device_info"></param>
        /// <param name="license_ids"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#39", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_enum_license_id32_windows(
                    [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
                    ref IntPtr license_ids);
        [DllImport(lib_name64, EntryPoint = "#39", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_enum_license_id64_windows(
                   [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
                   ref IntPtr license_ids);
        [DllImport(lib_name32, EntryPoint = "slm_enum_license_id")]
        public static extern UInt32 slm_enum_license_id32_linux(
            [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
            ref IntPtr license_ids);
        [DllImport(lib_name64, EntryPoint = "slm_enum_license_id")]
        public static extern UInt32 slm_enum_license_id64_linux(
                   [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
                   ref IntPtr license_ids);
        internal static UInt32 slm_enum_license_id(
                    [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
                    ref IntPtr license_ids)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_enum_license_id64_windows(device_info, ref license_ids);
                }
                return SlmRuntime.slm_enum_license_id32_windows(device_info, ref license_ids);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_enum_license_id64_linux(device_info, ref license_ids);
                }
                return SlmRuntime.slm_enum_license_id32_linux(device_info, ref license_ids);
            }
        }
        /// <summary>
        /// 枚举指定设备下所有许可ID
        /// </summary>
        /// <param name="device_info"></param>
        /// <param name="license_id"></param>
        /// <param name="license_info"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#40", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_license_info32_windows(
                    [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
                    UInt32 license_id,
                    ref IntPtr license_info);
        [DllImport(lib_name64, EntryPoint = "#40", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_license_info64_windows(
                    [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
                    UInt32 license_id,
                    ref IntPtr license_info);
        [DllImport(lib_name32, EntryPoint = "slm_get_license_info")]
        public static extern UInt32 slm_get_license_info32_linux(
            [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
            UInt32 license_id,
            ref IntPtr license_info);
        [DllImport(lib_name64, EntryPoint = "slm_get_license_info")]
        public static extern UInt32 slm_get_license_info64_linux(
                    [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
                    UInt32 license_id,
                    ref IntPtr license_info);
        internal static UInt32 slm_get_license_info(
                    [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
                    UInt32 license_id,
                    ref IntPtr license_info)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_license_info64_windows(device_info, license_id, ref license_info);
                }
                return SlmRuntime.slm_get_license_info32_windows(device_info, license_id, ref license_info);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_license_info64_linux(device_info, license_id, ref license_info);
                }
                return SlmRuntime.slm_get_license_info32_linux(device_info, license_id, ref license_info);
            }
        }
        /// <summary>
        /// 使用已登录的云许可进行签名（仅支持云锁）
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="sign_data"></param>
        /// <param name="sign_length"></param>
        ///  <param name="signature"></param>
        ///   <param name="max_buf_size"></param>
        ///    <param name="signature_length"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#41", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_license_sign32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
                    UInt32 sign_length,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                    UInt32 max_buf_size,
                    ref UInt32 signature_length);
        [DllImport(lib_name64, EntryPoint = "#41", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_license_sign64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
                    UInt32 sign_length,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                    UInt32 max_buf_size,
                    ref UInt32 signature_length);
        [DllImport(lib_name32, EntryPoint = "slm_license_sign")]
        public static extern UInt32 slm_license_sign32_linux(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
            UInt32 sign_length,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 max_buf_size,
            ref UInt32 signature_length);
        [DllImport(lib_name64, EntryPoint = "slm_license_sign")]
        public static extern UInt32 slm_license_sign64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
                    UInt32 sign_length,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                    UInt32 max_buf_size,
                    ref UInt32 signature_length);
        internal static UInt32 slm_license_sign(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
                    UInt32 sign_length,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                    UInt32 max_buf_size,
                    ref UInt32 signature_length)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_license_sign64_windows(slm_handle, sign_data, sign_length, signature, max_buf_size, ref signature_length);
                }
                return SlmRuntime.slm_license_sign32_windows(slm_handle, sign_data, sign_length, signature, max_buf_size, ref signature_length);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_license_sign64_linux(slm_handle, sign_data, sign_length, signature, max_buf_size, ref signature_length);
                }
                return SlmRuntime.slm_license_sign32_linux(slm_handle, sign_data, sign_length, signature, max_buf_size, ref signature_length);
            }
        }
        /// <summary>
        /// 对云许可签名后的数据进行验签（仅支持云锁）
        /// </summary>
        /// <param name="sign_data"></param>
        /// <param name="sign_length"></param>
        ///  <param name="signature"></param>
        ///   <param name="signature_length"></param>
        ///    <param name="sign_info"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#42", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_license_verify32_windows(
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
                    UInt32 sign_length,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                    UInt32 signature_length,
                    ref IntPtr sign_info);
        [DllImport(lib_name64, EntryPoint = "#42", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_license_verify64_windows(
                   [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
                   UInt32 sign_length,
                   [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                   UInt32 signature_length,
                   ref IntPtr sign_info);
        [DllImport(lib_name32, EntryPoint = "slm_license_verify")]
        public static extern UInt32 slm_license_verify32_linux(
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
            UInt32 sign_length,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 signature_length,
            ref IntPtr sign_info);
        [DllImport(lib_name64, EntryPoint = "slm_license_verify")]
        public static extern UInt32 slm_license_verify64_linux(
                   [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
                   UInt32 sign_length,
                   [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                   UInt32 signature_length,
                   ref IntPtr sign_info);
        internal static UInt32 slm_license_verify(
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
                    UInt32 sign_length,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
                    UInt32 signature_length,
                    ref IntPtr sign_info)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_license_verify64_windows(sign_data, sign_length, signature, signature_length, ref sign_info);
                }
                return SlmRuntime.slm_license_verify32_windows(sign_data, sign_length, signature, signature_length, ref sign_info);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_license_verify64_linux(sign_data, sign_length, signature, signature_length, ref sign_info);
                }
                return SlmRuntime.slm_license_verify32_linux(sign_data, sign_length, signature, signature_length, ref sign_info);
            }
        }
        /// <summary>
        /// 通过证书类型，获取已登录许可的设备证书
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="cert_type"></param>
        ///  <param name="cert"></param>
        ///   <param name="cert_size"></param>
        ///    <param name="cert_len"></param>
        /// <returns></returns>
        [DllImport(lib_name32, EntryPoint = "#43", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_cert32_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    CERT_TYPE cert_type,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] cert,
                    UInt32 cert_size,
                    ref UInt32 cert_len);
        [DllImport(lib_name64, EntryPoint = "#43", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_cert64_windows(
                    SLM_HANDLE_INDEX slm_handle,
                    CERT_TYPE cert_type,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] cert,
                    UInt32 cert_size,
                    ref UInt32 cert_len);
        [DllImport(lib_name32, EntryPoint = "slm_get_cert")]
        public static extern UInt32 slm_get_cert32_linux(
            SLM_HANDLE_INDEX slm_handle,
            CERT_TYPE cert_type,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] cert,
            UInt32 cert_size,
            ref UInt32 cert_len);
        [DllImport(lib_name64, EntryPoint = "slm_get_cert")]
        public static extern UInt32 slm_get_cert64_linux(
                    SLM_HANDLE_INDEX slm_handle,
                    CERT_TYPE cert_type,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] cert,
                    UInt32 cert_size,
                    ref UInt32 cert_len);
        internal static UInt32 slm_get_cert(
                    SLM_HANDLE_INDEX slm_handle,
                    CERT_TYPE cert_type,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] cert,
                    UInt32 cert_size,
                    ref UInt32 cert_len)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_cert64_windows(slm_handle, cert_type, cert, cert_size, ref cert_len);
                }
                return SlmRuntime.slm_get_cert32_windows(slm_handle, cert_type, cert, cert_size, ref cert_len);
            }
            else
            {
                if (SlmRuntime.Is64)
                {
                    return SlmRuntime.slm_get_cert64_linux(slm_handle, cert_type, cert, cert_size, ref cert_len);
                }
                return SlmRuntime.slm_get_cert32_linux(slm_handle, cert_type, cert, cert_size, ref cert_len);
            }
        }
    }
}