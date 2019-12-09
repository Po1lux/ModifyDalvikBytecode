package cn.pollux.modifydalvikbytecode;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;

import dalvik.system.DexFile;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("modify");
        modifyBytecode();
    }

    public static native int modifyBytecode();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        int t = Add.add(6,7);
        Log.i("cs","6+7="+t);
    }

}
