package com.silentsession.vault;

import com.silentsession.vault.ISessionCallback;
import android.os.Bundle;

interface ISessionService {
    int ver();
    String info();
    void subscribe(ISessionCallback cb);
    Bundle open(String tag);
    int state(String id);
    boolean step(String id, int slot, String tk, String p, in Bundle proof);
    String fetch(String id);
}
