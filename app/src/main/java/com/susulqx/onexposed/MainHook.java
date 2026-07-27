package com.susulqx.onexposed;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

/**
 * app.unique.one 签名校验绕过 — Xposed 模块
 *
 * 策略: Hook je8.oO0OO00([B) — MD5 转换器
 *   输入 >100 字节(APK 签名证书) → 返回原始签名的 MD5
 *   输入 <=100 字节(普通数据)     → 正常调用原始方法
 *
 * 覆盖:
 *   inc.oO0OO00() → nzc → je8   (启动校验)
 *   lcd.call()    → ... → je8   (周期校验)
 *
 * 不触发反检测:
 *   - 不修改 PackageManager → mPM 检测不过
 *   - 栈调试检测不过 → Xposed 无栈痕迹
 *   - Native 层 check() 未被调用
 */
public class MainHook implements IXposedHookLoadPackage {

    /**
     * [已确认] 原始签名 MD5
     * 来源: inc.smali:339 Base64 解码 + Frida 篡改验证
     */
    private static final String EXPECTED_SIGNATURE_MD5 = "34a84f483661b9b112fc8a34a77a2331";

    /**
     * [已确认] X.509 证书最小字节数 (实际 690B)
     */
    private static final int CERTIFICATE_MIN_BYTES = 100;

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) {
        if (!"app.unique.one".equals(lpparam.packageName)) {
            return;
        }

        XposedBridge.log("[OneXposed] Loading into " + lpparam.packageName);

        try {
            // je8.oO0OO00([B)Ljava/lang/String;
            // 这是签名 MD5 转换的核心工具类
            // 启动校验 (inc→nzc→je8) 和周期校验 (lcd→je8) 均汇聚于此
            XposedHelpers.findAndHookMethod(
                "je8",
                lpparam.classLoader,
                "oO0OO00",
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        byte[] input = (byte[]) param.args[0];
                        if (input != null && input.length > CERTIFICATE_MIN_BYTES) {
                            // 签名证书 → 返回原始正确 MD5, 绕过校验
                            param.setResult(EXPECTED_SIGNATURE_MD5);
                        }
                        // 普通数据 → 不干预, 让原始方法正常执行
                    }
                }
            );

            XposedBridge.log("[OneXposed] je8.oO0OO00 hooked successfully");

        } catch (Throwable t) {
            XposedBridge.log("[OneXposed] Hook failed: " + t.getMessage());
            XposedBridge.log(t);
        }
    }
}
