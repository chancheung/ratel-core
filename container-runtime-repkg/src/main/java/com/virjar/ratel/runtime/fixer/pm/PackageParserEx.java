package com.virjar.ratel.runtime.fixer.pm;


import android.content.pm.PackageParser;
import android.content.pm.Signature;
import android.database.Cursor;
import android.net.Uri;
import android.os.Environment;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Base64;
import android.util.Log;

import com.virjar.ratel.allcommon.Constants;
import com.virjar.ratel.api.rposed.RposedHelpers;
import com.virjar.ratel.runtime.RatelEnvironment;
import com.virjar.ratel.runtime.RatelRuntime;
import com.virjar.ratel.runtime.XposedModuleLoader;
import com.virjar.ratel.runtime.ipc.ClientHandlerServiceConnection;
import com.virjar.ratel.utils.BuildCompat;
import com.virjar.ratel.utils.FileUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Lody
 */

public class PackageParserEx {

    private static final String TAG = Constants.TAG;
    private static Signature[] mSignature = null;
    private static Map<String, SignatureOptional> fakeSignatureCache = new ConcurrentHashMap<>();
    private static final java.lang.String WX_APP_SIGNATURE = "308202eb30820254a00302010202044d36f7a4300d06092a864886f70d01010505003081b9310b300906035504061302383631123010060355040813094775616e67646f6e673111300f060355040713085368656e7a68656e31353033060355040a132c54656e63656e7420546563686e6f6c6f6779285368656e7a68656e2920436f6d70616e79204c696d69746564313a3038060355040b133154656e63656e74204775616e677a686f7520526573656172636820616e6420446576656c6f706d656e742043656e7465723110300e0603550403130754656e63656e74301e170d3131303131393134333933325a170d3431303131313134333933325a3081b9310b300906035504061302383631123010060355040813094775616e67646f6e673111300f060355040713085368656e7a68656e31353033060355040a132c54656e63656e7420546563686e6f6c6f6779285368656e7a68656e2920436f6d70616e79204c696d69746564313a3038060355040b133154656e63656e74204775616e677a686f7520526573656172636820616e6420446576656c6f706d656e742043656e7465723110300e0603550403130754656e63656e7430819f300d06092a864886f70d010101050003818d0030818902818100c05f34b231b083fb1323670bfbe7bdab40c0c0a6efc87ef2072a1ff0d60cc67c8edb0d0847f210bea6cbfaa241be70c86daf56be08b723c859e52428a064555d80db448cdcacc1aea2501eba06f8bad12a4fa49d85cacd7abeb68945a5cb5e061629b52e3254c373550ee4e40cb7c8ae6f7a8151ccd8df582d446f39ae0c5e930203010001300d06092a864886f70d0101050500038181009c8d9d7f2f908c42081b4c764c377109a8b2c70582422125ce545842d5f520aea69550b6bd8bfd94e987b75a3077eb04ad341f481aac266e89d3864456e69fba13df018acdc168b9a19dfd7ad9d9cc6f6ace57c746515f71234df3a053e33ba93ece5cd0fc15f3e389a3f365588a9fcb439e069d3629cd7732a13fff7b891499";
    private static final java.lang.String WB_APP_SIGNATURE = "30820295308201fea00302010202044b4ef1bf300d06092a864886f70d010105050030818d310b300906035504061302434e3110300e060355040813074265694a696e673110300e060355040713074265694a696e67312c302a060355040a132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c7464312c302a060355040b132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c74643020170d3130303131343130323831355a180f32303630303130323130323831355a30818d310b300906035504061302434e3110300e060355040813074265694a696e673110300e060355040713074265694a696e67312c302a060355040a132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c7464312c302a060355040b132353696e612e436f6d20546563686e6f6c6f677920284368696e612920436f2e204c746430819f300d06092a864886f70d010101050003818d00308189028181009d367115bc206c86c237bb56c8e9033111889b5691f051b28d1aa8e42b66b7413657635b44786ea7e85d451a12a82a331fced99c48717922170b7fc9bc1040753c0d38b4cf2b22094b1df7c55705b0989441e75913a1a8bd2bc591aa729a1013c277c01c98cbec7da5ad7778b2fad62b85ac29ca28ced588638c98d6b7df5a130203010001300d06092a864886f70d0101050500038181000ad4b4c4dec800bd8fd2991adfd70676fce8ba9692ae50475f60ec468d1b758a665e961a3aedbece9fd4d7ce9295cd83f5f19dc441a065689d9820faedbb7c4a4c4635f5ba1293f6da4b72ed32fb8795f736a20c95cda776402099054fccefb4a1a558664ab8d637288feceba9508aa907fc1fe2b1ae5a0dec954ed831c0bea4";
    private static final java.lang.String XHS_APP_SIGNATURE = "3082024d308201b6a003020102020453c638a2300d06092a864886f70d0101050500306b310b30090603550406130238363111300f060355040813087368616e676861693111300f060355040713087368616e67686169310f300d060355040a130678696e67696e310f300d060355040b130678696e67696e311430120603550403130b7869616f686f6e67736875301e170d3134303731363038333233345a170d3339303731303038333233345a306b310b30090603550406130238363111300f060355040813087368616e676861693111300f060355040713087368616e67686169310f300d060355040a130678696e67696e310f300d060355040b130678696e67696e311430120603550403130b7869616f686f6e6773687530819f300d06092a864886f70d010101050003818d00308189028181009d9ed5a4a85dd8a2117bc8afdcbf944de13f28e068e1b51492c0cba6882f07bba9eeb1ab2911182246f89d227db3f358fe49c3ffb7d7de7592add1ac74bf125aedc7191420cf632d2c163898c601ac85c0bc90e7d932763e9454128ae33994f5cc622cb3d42448ae4da94636d9fb32b4c5006a7abcec322691706c8eefa482650203010001300d06092a864886f70d010105050003818100098b8d055d87c6e76a633b1b2283bca2408a17acd4302c3863b23027239b1e78ff2fc42393a1981c78d6b7a207301f4b97ea0f3b79dcb9a9221044d2b6aa3532960c49e4bdcce0afb2c53abaa94ae2280c32bdb809ac3bcf3cecbe81e0eefd875bc6cd60dcb024cc5a3221bb76fa88f8e2d9651308868f07374109030ccc3c99";

    static {
        // 已存的系统签名，这样没有容器感染微信也可以调用微信api
        createWellKnownSignature("com.tencent.mm", WX_APP_SIGNATURE);
        createWellKnownSignature("com.sina.weibo", WB_APP_SIGNATURE);
        createWellKnownSignature("com.xingin.xhs", XHS_APP_SIGNATURE);
    }

    private static void createWellKnownSignature(String pkg, String signatureData) {
        SignatureOptional signatureOptional = new SignatureOptional();
        signatureOptional.packageName = pkg;
        signatureOptional.signatures = new Signature[]{new Signature(signatureData)};
        fakeSignatureCache.put(signatureOptional.packageName, signatureOptional);
    }


    private static class SignatureOptional {
        Signature[] signatures = null;
        String packageName;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SignatureOptional that = (SignatureOptional) o;
            return Objects.equals(packageName, that.packageName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(packageName);
        }
    }


    public static Signature[] getFakeSignature(String packageName) {
        if (RatelRuntime.nowPackageName.equals(packageName)) {
            Signature[] ret = getFakeSignatureForOwner();
            try {
                saveSignatureToManager(ret);
            } catch (IOException e) {
                Log.e(Constants.TAG, "save signature data failed", e);
            }
            return ret;
        }

        SignatureOptional signatures = fakeSignatureCache.get(packageName);
        if (signatures != null) {
            return signatures.signatures;
        }

        SignatureOptional signatureOptional = queryFakeSignature(packageName);

        fakeSignatureCache.put(packageName, signatureOptional);
        return signatureOptional.signatures;

    }


    private static SignatureOptional queryFakeSignature(String packageName) {
        //ipc call content provider first
        SignatureOptional ret = new SignatureOptional();
        ret.packageName = packageName;
        try {
            Cursor cursor = RatelRuntime.getOriginContext().getContentResolver().query(
                    Uri.parse("content://com.virjar.ratel.manager/fake_signature"),
                    null,
                    "mPackage=?",
                    new String[]{packageName},
                    null
            );
            if (cursor != null) {
                ret = new SignatureOptional();

                if (cursor.moveToNext()) {
                    String signatureBase64 = cursor.getString(cursor.getColumnIndex("signature"));
                    ret.signatures = decode(signatureBase64);
                }
                cursor.close();
                return ret;
            } else {
                Log.w(Constants.TAG, "get fake signature data cursor return null");
            }
        } catch (Exception e) {
            Log.w(Constants.TAG, "failed to get fake signature data cursor!!", e);
        }

        //then try with sdcard
        boolean canSdcardRead = XposedModuleLoader.testHasSDCardReadPermission();
        if (canSdcardRead) {
            File ratelConfigRoot = new File(Environment.getExternalStorageDirectory(), Constants.ratelSDCardRoot);
            File fakeSignatureDir = new File(ratelConfigRoot, Constants.fakeSignatureDir);
            File fakeSignatureFile = new File(fakeSignatureDir, packageName + ".txt");

            if (fakeSignatureFile.exists() && fakeSignatureFile.canRead()) {
                try {
                    ret.signatures = decode(external.org.apache.commons.io.FileUtils.readFileToString(fakeSignatureFile, StandardCharsets.UTF_8));
                } catch (IOException e) {
                    Log.w(Constants.TAG, "failed to read fakeSignatureFile: " + fakeSignatureFile.getAbsolutePath());
                }
            }
        }
        return ret;
    }

    private static Signature[] decode(String base64String) {
        byte[] bytes = Base64.decode(base64String, 0);
        Parcel p = Parcel.obtain();
        try {
            p.unmarshall(bytes, 0, bytes.length);
            p.setDataPosition(0);
            return p.createTypedArray(Signature.CREATOR);
        } finally {
            p.recycle();
        }
    }


    public static Signature[] getFakeSignatureForOwner() {
        Signature[] signatures = mSignature;
        if (signatures != null) {
            return signatures;
        }
        signatures = readSignature();
        if (signatures != null) {
            return signatures;
        }

        try {
            Signature[] fakeSignatureInternal = getFakeSignatureInternal(RatelEnvironment.originApkDir());
            mSignature = fakeSignatureInternal;
            savePackageCache(fakeSignatureInternal);
            return fakeSignatureInternal;
        } catch (Throwable throwable) {
            Log.e(TAG, "签名读取失败", throwable);
            throw new RuntimeException(throwable);
        }
    }

    private static Signature[] getFakeSignatureInternal(File packageFile) throws Throwable {
        PackageParser parser = PackageParserCompat.createParser(packageFile);
        if (BuildCompat.isQ()) {
            //请注意，不能直接这么访问，原因是 hidden API，需要通过双段反射来操作
            PackageParser.CallbackImpl callbackImpl = (PackageParser.CallbackImpl) RposedHelpers.newInstance(PackageParser.CallbackImpl.class, RatelRuntime.getOriginContext().getPackageManager());
            RposedHelpers.callMethod(parser, "setCallback", callbackImpl);
            // parser.setCallback(new PackageParser.CallbackImpl(RatelRuntime.getOriginContext().getPackageManager()));
        }

        PackageParser.Package p = PackageParserCompat.parsePackage(parser, packageFile, 0);
        if (p.requestedPermissions.contains("android.permission.FAKE_PACKAGE_SIGNATURE")
                && p.mAppMetaData != null
                && p.mAppMetaData.containsKey("fake-signature")) {
            String sig = p.mAppMetaData.getString("fake-signature");
            //p.mSignatures = new Signature[]{new Signature(sig)};
            //android 10更新
            buildSignature(p, new Signature[]{new Signature(sig)});
            Log.i(TAG, "Using fake-signature feature on : " + p.packageName);
        } else {
            PackageParserCompat.collectCertificates(parser, p, PackageParser.PARSE_IS_SYSTEM);
        }
        if (BuildCompat.isPie()) {
            return p.mSigningDetails.signatures;
        } else {
            return p.mSignatures;
        }
    }

    private static void buildSignature(PackageParser.Package packageR, Signature[] signatureArr) {
        if (BuildCompat.isQ()) {
            Object obj = mirror.android.content.pm.PackageParser.Package.mSigningDetails.get(packageR);
            mirror.android.content.pm.PackageParser.SigningDetails.pastSigningCertificates.set(obj, signatureArr);
            mirror.android.content.pm.PackageParser.SigningDetails.signatures.set(obj, signatureArr);
            return;
        }
        packageR.mSignatures = signatureArr;
    }

    private static Signature[] readSignature() {
        File signatureFile = RatelEnvironment.originAPKSignatureFile();
        if (!signatureFile.exists()) {
            return null;
        }
        Parcel p = Parcel.obtain();
        try {
            FileInputStream fis = new FileInputStream(signatureFile);
            byte[] bytes = FileUtils.toByteArray(fis);
            fis.close();
            p.unmarshall(bytes, 0, bytes.length);
            p.setDataPosition(0);
            return p.createTypedArray(Signature.CREATOR);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            p.recycle();
        }
        return null;
    }


    private static void savePackageCache(Signature[] signatures) {
        if (signatures == null) {
            return;
        }
        File signatureFile = RatelEnvironment.originAPKSignatureFile();
        if (signatureFile.exists() && !signatureFile.delete()) {
            Log.w(TAG, "Unable to delete the signatures  file:  " + signatureFile);
        }
        Parcel p = Parcel.obtain();
        try {
            p.writeTypedArray(signatures, 0);
            FileUtils.writeParcelToFile(p, signatureFile);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            p.recycle();
        }

    }

    private static boolean hasSave = false;

    private static void saveSignatureToManager(Signature[] signatures) throws IOException {
        if (signatures == null) {
            return;
        }

        if (hasSave) {
            return;
        }

        String encodeSignatureData;
        Parcel p = Parcel.obtain();
        try {
            p.writeTypedArray(signatures, 0);
            byte[] bytes = p.marshall();
            encodeSignatureData = Base64.encodeToString(bytes, 0);
        } finally {
            p.recycle();
        }


        //ipc save
        String finalEncodeSignatureData = encodeSignatureData;
        ClientHandlerServiceConnection.addOnManagerIPCListener(iRatelManagerClientRegister -> {
            if (XposedModuleLoader.getRatelManagerVersionCode() < 4) {
                //1.0.4之前不支持通过manager存储
                return;
            }

            try {
                iRatelManagerClientRegister.saveMSignature(RatelRuntime.nowPackageName, finalEncodeSignatureData);
            } catch (RemoteException e) {
                Log.e(Constants.TAG, "save mSignature data failed", e);
            }
        });

        //sdcard save
        if (!XposedModuleLoader.testHasSDCardWritePermission()) {
            return;
        }

        File ratelConfigRoot = new File(Environment.getExternalStorageDirectory(), Constants.ratelSDCardRoot);
        File fakeSignatureDir = new File(ratelConfigRoot, Constants.fakeSignatureDir);
        File fakeSignatureFile = new File(fakeSignatureDir, RatelRuntime.nowPackageName + ".txt");

        external.org.apache.commons.io.FileUtils.forceMkdirParent(fakeSignatureFile);
        external.org.apache.commons.io.FileUtils.writeStringToFile(fakeSignatureFile, encodeSignatureData, StandardCharsets.UTF_8);

        hasSave = true;
    }

}
