/**
 * 
 */
package cn.edu.ncepu.crypto.utils;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @版权 : Copyright (c) 2018-2019 E1101智能电网信息安全中心
 * @author: Hu Baiji
 * @E-mail: drbjhu@163.com
 * @创建日期: 2019年10月16日 下午7:44:24
 * @ClassName TimeCountProxyHandle
 * @类描述-Description:  时间统计处理机，用于统计各方法耗时
 * @修改记录:
 * @版本: 1.0
 */
public class TimeCountProxyHandle implements InvocationHandler {

	private static final Logger logger = LoggerFactory.getLogger(TimeCountProxyHandle.class);
	private final Object proxied;

	public TimeCountProxyHandle(Object obj) {
		proxied = obj;
	}

	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		//   Auto-generated method stub
		long begin = System.currentTimeMillis();
		Object result = method.invoke(proxied, args);
		long end = System.currentTimeMillis();
		logger.info(method.getName() + "耗时:" + (end - begin) + "ms");
		return result;
	}

}
