/**
 * 
 */
package cn.edu.ncepu.crypto.utils;

import java.io.File;

/**
 * @Copyright : Copyright (c) 2020-2021 
 * @author: Baiji Hu
 * @E-mail: drbjhu@163.com
 * @Version: 1.0
 * @CreateData: Jun 26, 2020 4:21:06 PM
 * @ClassName SysProperty
 * @Description:  (System.getProperty详解)
 */

@SuppressWarnings("all")
public class SysProperty {

	/**
	 * java.version   						Java 运行时环境版本
	 * java.vendor    						Java 运行时环境供应商
	 * java.vendor.url 						Java 供应商的 URL
	 * java.home 							Java 安装目录
	 * java.vm.specification.version        Java 虚拟机规范版本
	 * java.vm.specification.vendor			Java 虚拟机规范供应商
	 * java.vm.specification.name			Java 虚拟机规范名称
	 * java.vm.version						Java 虚拟机实现版本
	 * java.vm.vendor						Java 虚拟机实现供应商
	 * java.vm.name							Java 虚拟机实现名称
	 * java.specification.version			Java 运行时环境规范版本
	 * java.specification.vendor			Java 运行时环境规范供应商
	 * java.specification.name				Java 运行时环境规范名称
	 * java.class.version					Java 类格式版本号
	 * java.class.path						Java 类路径
	 * java.library.path					加载库时搜索的路径列表
	 * java.io.tmpdir						默认的临时文件路径
	 * java.compiler						要使用的 JIT 编译器的名称
	 * java.ext.dirs						一个或多个扩展目录的路径
	 * os.name								操作系统的名称
	 * os.arch								操作系统的架构
	 * os.version							操作系统的版本
	 * file.separator						文件分隔符（在 UNIX 系统中是“/”）
	 * path.separator						路径分隔符（在 UNIX 系统中是“:”）
	 * line.separator						行分隔符（在 UNIX 系统中是“/n”）
	 * user.name							用户的账户名称
	 * user.home							用户的主目录
	 * user.dir								用户的当前工作目录
	 */

	private static final String OS_NAME_WINDOWS_PREFIX = "Windows";
	private static final String USER_HOME_KEY = "user.home";
	private static final String USER_DIR_KEY = "user.dir";
	private static final String JAVA_IO_TMPDIR_KEY = "java.io.tmpdir";
	private static final String JAVA_HOME_KEY = "java.home";
	public static final String AWT_TOOLKIT = getSystemProperty("awt.toolkit");

	public static final String FILE_ENCODING = getSystemProperty("file.encoding");

	public static final String FILE_SEPARATOR = getSystemProperty("file.separator");

	public static final String JAVA_AWT_FONTS = getSystemProperty("java.awt.fonts");

	public static final String JAVA_AWT_GRAPHICSENV = getSystemProperty("java.awt.graphicsenv");

	public static final String JAVA_AWT_HEADLESS = getSystemProperty("java.awt.headless");

	public static final String JAVA_AWT_PRINTERJOB = getSystemProperty("java.awt.printerjob");

	public static final String JAVA_CLASS_PATH = getSystemProperty("java.class.path");

	public static final String JAVA_CLASS_VERSION = getSystemProperty("java.class.version");

	public static final String JAVA_COMPILER = getSystemProperty("java.compiler");

	public static final String JAVA_ENDORSED_DIRS = getSystemProperty("java.endorsed.dirs");

	public static final String JAVA_EXT_DIRS = getSystemProperty("java.ext.dirs");

	public static final String JAVA_HOME = getSystemProperty("java.home");

	public static final String JAVA_IO_TMPDIR = getSystemProperty("java.io.tmpdir");

	public static final String JAVA_LIBRARY_PATH = getSystemProperty("java.library.path");

	public static final String JAVA_RUNTIME_NAME = getSystemProperty("java.runtime.name");

	public static final String JAVA_RUNTIME_VERSION = getSystemProperty("java.runtime.version");

	public static final String JAVA_SPECIFICATION_NAME = getSystemProperty("java.specification.name");

	public static final String JAVA_SPECIFICATION_VENDOR = getSystemProperty("java.specification.vendor");

	public static final String JAVA_SPECIFICATION_VERSION = getSystemProperty("java.specification.version");

	public static final String JAVA_UTIL_PREFS_PREFERENCES_FACTORY = getSystemProperty(
			"java.util.prefs.PreferencesFactory");

	public static final String JAVA_VENDOR = getSystemProperty("java.vendor");

	public static final String JAVA_VENDOR_URL = getSystemProperty("java.vendor.url");

	public static final String JAVA_VERSION = getSystemProperty("java.version");

	public static final String JAVA_VM_INFO = getSystemProperty("java.vm.info");

	public static final String JAVA_VM_NAME = getSystemProperty("java.vm.name");

	public static final String JAVA_VM_SPECIFICATION_NAME = getSystemProperty("java.vm.specification.name");

	public static final String JAVA_VM_SPECIFICATION_VENDOR = getSystemProperty("java.vm.specification.vendor");

	public static final String JAVA_VM_SPECIFICATION_VERSION = getSystemProperty("java.vm.specification.version");

	public static final String JAVA_VM_VENDOR = getSystemProperty("java.vm.vendor");

	public static final String JAVA_VM_VERSION = getSystemProperty("java.vm.version");

	public static final String LINE_SEPARATOR = getSystemProperty("line.separator");

	public static final String OS_ARCH = getSystemProperty("os.arch");

	public static final String OS_NAME = getSystemProperty("os.name");

	public static final String OS_VERSION = getSystemProperty("os.version");

	public static final String PATH_SEPARATOR = getSystemProperty("path.separator");

	public static final String USER_COUNTRY = getSystemProperty("user.country") == null
			? getSystemProperty("user.region")
			: getSystemProperty("user.country");

	public static final String USER_DIR = getSystemProperty("user.dir");

	public static final String USER_HOME = getSystemProperty("user.home");

	public static final String USER_LANGUAGE = getSystemProperty("user.language");

	public static final String USER_NAME = getSystemProperty("user.name");

	public static final String USER_TIMEZONE = getSystemProperty("user.timezone");

	public static final String JAVA_VERSION_TRIMMED = getJavaVersionTrimmed();

	public static final float JAVA_VERSION_FLOAT = getJavaVersionAsFloat();

	public static final int JAVA_VERSION_INT = getJavaVersionAsInt();

	public static final boolean IS_JAVA_1_1 = getJavaVersionMatches("1.1");

	public static final boolean IS_JAVA_1_2 = getJavaVersionMatches("1.2");

	public static final boolean IS_JAVA_1_3 = getJavaVersionMatches("1.3");

	public static final boolean IS_JAVA_1_4 = getJavaVersionMatches("1.4");

	public static final boolean IS_JAVA_1_5 = getJavaVersionMatches("1.5");

	public static final boolean IS_JAVA_1_6 = getJavaVersionMatches("1.6");

	public static final boolean IS_OS_AIX = getOSMatches("AIX");

	public static final boolean IS_OS_HP_UX = getOSMatches("HP-UX");

	public static final boolean IS_OS_IRIX = getOSMatches("Irix");

	public static final boolean IS_OS_LINUX = (getOSMatches("Linux")) || (getOSMatches("LINUX"));

	public static final boolean IS_OS_MAC = getOSMatches("Mac");

	public static final boolean IS_OS_MAC_OSX = getOSMatches("Mac OS X");

	public static final boolean IS_OS_OS2 = getOSMatches("OS/2");

	public static final boolean IS_OS_SOLARIS = getOSMatches("Solaris");

	public static final boolean IS_OS_SUN_OS = getOSMatches("SunOS");

	public static final boolean IS_OS_UNIX = (IS_OS_AIX) || (IS_OS_HP_UX) || (IS_OS_IRIX) || (IS_OS_LINUX)
			|| (IS_OS_MAC_OSX) || (IS_OS_SOLARIS) || (IS_OS_SUN_OS);

	public static final boolean IS_OS_WINDOWS = getOSMatches("Windows");

	public static final boolean IS_OS_WINDOWS_2000 = getOSMatches("Windows", "5.0");

	public static final boolean IS_OS_WINDOWS_95 = getOSMatches("Windows 9", "4.0");

	public static final boolean IS_OS_WINDOWS_98 = getOSMatches("Windows 9", "4.1");

	public static final boolean IS_OS_WINDOWS_ME = getOSMatches("Windows", "4.9");

	public static final boolean IS_OS_WINDOWS_NT = getOSMatches("Windows NT");

	public static final boolean IS_OS_WINDOWS_XP = getOSMatches("Windows", "5.1");

	/** @deprecated */
	public static float getJavaVersion() {
		return JAVA_VERSION_FLOAT;
	}

	private static float getJavaVersionAsFloat() {
		if (JAVA_VERSION_TRIMMED == null) {
			return 0.0F;
		}
		String str = JAVA_VERSION_TRIMMED.substring(0, 3);
		if (JAVA_VERSION_TRIMMED.length() >= 5)
			str = str + JAVA_VERSION_TRIMMED.substring(4, 5);
		try {
			return Float.parseFloat(str);
		} catch (Exception ex) {
		}
		return 0.0F;
	}

	private static int getJavaVersionAsInt() {
		if (JAVA_VERSION_TRIMMED == null) {
			return 0;
		}
		String str = JAVA_VERSION_TRIMMED.substring(0, 1);
		str = str + JAVA_VERSION_TRIMMED.substring(2, 3);
		if (JAVA_VERSION_TRIMMED.length() >= 5)
			str = str + JAVA_VERSION_TRIMMED.substring(4, 5);
		else
			str = str + "0";
		try {
			return Integer.parseInt(str);
		} catch (Exception ex) {
		}
		return 0;
	}

	private static String getJavaVersionTrimmed() {
		if (JAVA_VERSION != null) {
			for (int i = 0; i < JAVA_VERSION.length(); i++) {
				char ch = JAVA_VERSION.charAt(i);
				if ((ch >= '0') && (ch <= '9')) {
					return JAVA_VERSION.substring(i);
				}
			}
		}
		return null;
	}

	private static boolean getJavaVersionMatches(String versionPrefix) {
		if (JAVA_VERSION_TRIMMED == null) {
			return false;
		}
		return JAVA_VERSION_TRIMMED.startsWith(versionPrefix);
	}

	private static boolean getOSMatches(String osNamePrefix) {
		if (OS_NAME == null) {
			return false;
		}
		return OS_NAME.startsWith(osNamePrefix);
	}

	private static boolean getOSMatches(String osNamePrefix, String osVersionPrefix) {
		if ((OS_NAME == null) || (OS_VERSION == null)) {
			return false;
		}
		return (OS_NAME.startsWith(osNamePrefix)) && (OS_VERSION.startsWith(osVersionPrefix));
	}

	private static String getSystemProperty(String property) {
		try {
			return System.getProperty(property);
		} catch (SecurityException ex) {
			System.err.println("Caught a SecurityException reading the system property '" + property
					+ "'; the SystemUtils property value will default to null.");
		}

		return null;
	}

	public static boolean isJavaVersionAtLeast(float requiredVersion) {
		return JAVA_VERSION_FLOAT >= requiredVersion;
	}

	public static boolean isJavaVersionAtLeast(int requiredVersion) {
		return JAVA_VERSION_INT >= requiredVersion;
	}

	public static boolean isJavaAwtHeadless() {
		return JAVA_AWT_HEADLESS != null ? JAVA_AWT_HEADLESS.equals(Boolean.TRUE.toString()) : false;
	}

	public static File getJavaHome() {
		return new File(System.getProperty("java.home"));
	}

	public static File getJavaIoTmpDir() {
		return new File(System.getProperty("java.io.tmpdir"));
	}

	public static File getUserDir() {
		return new File(System.getProperty("user.dir"));
	}

	public static File getUserHome() {
		return new File(System.getProperty("user.home"));
	}

//--------------------------------------------------------------------------------------------------
	/**获取操作系统名称*/
	private static String osName() {
		return System.getProperty("os.name");
	}

	/**获取操作系统版本*/
	private static String osVersion() {
		return System.getProperty("os.version");
	}

	/**获取Java运行时环境供应商*/
	private static String vendor() {
		return System.getProperty("java.vendor");
	}

	/**获取Java供应商的 URL*/
	private static String vendorUrl() {
		return System.getProperty("java.vendor.url");
	}

	/**Java 安装目录*/
	private static String home() {
		return System.getProperty("java.home");
	}

	/**获取类的版本*/
	private static String classVersion() {
		return System.getProperty("java.class.version");
	}

	/**
	 * Java 类路径
	 * @return
	 */
	private static String classPath() {
		return System.getProperty("java.class.path");
	}

	/**
	 * 操作系统的架构
	 * @return
	 */
	private static String osArch() {

		return System.getProperty("os.arch");
	}

	/**
	 * 获取用户的账户名称
	 * @return
	 */
	private static String userName() {
		return System.getProperty("user.name");
	}

	/**
	 * 获取用户的主目录
	 * @return
	 */
	private static String userHome() {
		return System.getProperty("user.home");
	}

	/**
	 * 用户的当前工作目录
	 * @return
	 */
	private static String userDir() {
		return System.getProperty("user.dir");
	}

	/**
	 * Java 虚拟机规范版本
	 * @return
	 */
	private static String vmSpecificationVersion() {
		return System.getProperty("java.vm.specification.version");
	}

	/**
	 * Java 虚拟机规范供应商
	 * @return
	 */
	private static String vmSpecificationVendor() {
		return System.getProperty("java.vm.specification.vendor");
	}

	/**
	 * Java 虚拟机规范名称
	 * @return
	 */
	private static String vmSpecificationName() {
		return System.getProperty("java.vm.specification.name");
	}

	/**
	 * Java 虚拟机实现版本
	 * @return
	 */
	private static String vmVersion() {
		return System.getProperty("java.vm.version");
	}

	/**
	 * Java 虚拟机实现供应商
	 * @return
	 */
	private static String vmVendor() {
		return System.getProperty("java.vm.vendor");
	}

	/**
	 * Java 虚拟机实现名称
	 * @return
	 */
	private static String vmName() {
		return System.getProperty("java.vm.name");
	}

	/**
	 * 一个或多个扩展目录的路径
	 * @return
	 */
	private static String extDirs() {
		return System.getProperty("java.ext.dirs");
	}

	/**
	 *加载库时搜索的路径列表
	 * @return
	 */
	private static String library() {
		return System.getProperty("java.library.path");
	}

	/**
	 * 文件分隔符（在 UNIX 系统中是“/”）
	 * @return
	 */
	private static String fileSeparator() {
		return System.getProperty("file.separator");
	}

	/**
	 * 路径分隔符（在 UNIX 系统中是“:”）
	 * @return
	 */
	private static String pathSeparator() {
		return System.getProperty("path.separator");
	}

	/**
	 * 行分隔符（在 UNIX 系统中是“/n”）
	 * @return
	 */
	private static String lineSeparator() {
		return System.getProperty("line.separator");
	}

	/**
	 * 要使用的 JIT 编译器的名称
	 * @return
	 */
	private static String compiler() {
		return System.getProperty("java.compiler");
	}

	/**
	 * C:\Users\ADMINI~1\AppData\Local\Temp\ 获取当前临时目录
	 * 
	 * @return
	 */
	public static String getSystempPath() {
		return System.getProperty("java.io.tmpdir");
	}

	/**
	 * 以\分割
	 * 
	 * @return
	 */
	public static String getSeparator() {
		return System.getProperty("file.separator");
	}

	/**
	 * 如:file:/D:/Workspaces/MyEclipse%208.6/myapp/WebRoot/WEB-INF/classes/未处理
	 * 处理后：D:\Workspaces\MyEclipse%208.6\napp\WebRoot\ 获取当前项目的路径
	 * 
	 * @return
	 */
	public static String getSysPath() {
		String path = Thread.currentThread().getContextClassLoader().getResource("").toString();
//		logger.info(path);
		String temp = path.replaceFirst("file:/", "").replaceFirst("WEB-INF/classes/", "");
		String separator = System.getProperty("file.separator");
		String resultPath = temp.replaceAll("/", separator + separator);
		return resultPath;
	}

	/**
	 * 未处理 D:/Workspaces/MyEclipse%208.6/myapp/WebRoot/WEB-INF/classes/ 已处理
	 * D:\Workspaces\MyEclipse%208.6\myapp\WebRoot\WEB-INF\classes\
	 * 
	 * @return
	 */
	public static String getClassPath() {
		String path = Thread.currentThread().getContextClassLoader().getResource("").toString();
		String temp = path.replaceFirst("file:/", "");
		String separator = System.getProperty("file.separator");
		String resultPath = temp.replaceAll("/", separator + separator);
		return resultPath;
	}

}
