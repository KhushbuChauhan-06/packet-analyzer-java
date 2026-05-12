package com.dpi.engine;

import com.dpi.types.AppType;
import com.dpi.types.FiveTuple;

/** Tracks state and classification for a single network flow */
public class FlowEntry {
    public FiveTuple tuple;
    public AppType   appType    = AppType.UNKNOWN;
    public String    sni        = "";
    public long      packets    = 0;
    public long      bytes      = 0;
    public boolean   blocked    = false;
    public boolean   classified = false;
}