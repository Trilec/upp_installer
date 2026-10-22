#include "InstallerCore.h"
namespace Upp { namespace Installer {
namespace {
bool Fields(const Value& value,const String& allowed) {
    if(!value.Is<ValueMap>()) return false;
    ValueMap map=value; Index<String> seen;
    for(int i=0;i<map.GetCount();++i) {
        if(!map.GetKey(i).Is<String>()) return false;
        String key=map.GetKey(i);
        if(key.Find('|')>=0 || ("|"+allowed+"|").Find("|"+key+"|")<0 || seen.Find(key)>=0) return false;
        seen.Add(key);
    }
    return true;
}
bool Text(const Value& v,int maximum=4096) {
    if(!v.Is<String>() || String(v).IsEmpty() || String(v).GetCount()>maximum) return false;
    for(int ch:String(v)) if(ch<32 || ch==127) return false;
    return true;
}
bool Integer(const Value& v,int low,int high) { return IsNumber(v) && !v.Is<bool>() && (double)v>=low && (double)v<=high && (double)v==(int)v; }
bool Hash(const Value& v) { if(!v.Is<String>() || String(v).GetCount()!=64) return false; for(int ch:String(v)) if(!IsXDigit(ch)) return false; return true; }
bool Structure(const Value& v,int depth=0) {
    if(depth>32) return false;
    if(v.Is<ValueMap>()) { ValueMap m=v; Index<String> keys; for(int i=0;i<m.GetCount();++i) { if(!m.GetKey(i).Is<String>() || keys.Find(String(m.GetKey(i)))>=0 || !Structure(m.GetValue(i),depth+1)) return false; keys.Add(String(m.GetKey(i))); } }
    if(v.Is<ValueArray>()) for(const Value& child:(ValueArray)v) if(!Structure(child,depth+1)) return false;
    return true;
}
bool Args(const Value& v) { if(!v.Is<ValueArray>() || v.GetCount()>64) return false; for(const Value& arg:(ValueArray)v) if(!arg.Is<String>() || String(arg).Find('\0')>=0 || String(arg).GetCount()>4096) return false; return true; }
}
String PlatformName() {
#ifdef PLATFORM_WIN32
    return "windows";
#elif defined(PLATFORM_OSX)
    return "macos";
#else
    return "linux";
#endif
}
bool RelativePath(const String& path) {
    if(path.IsEmpty() || path.GetCount()>1024 || IsFullPath(path) || path.Find('\\')>=0 || path.Find(':')>=0 || path.StartsWith("/") || path.EndsWith("/")) return false;
    for(int ch:path) if(ch<32 || ch==127 || ch=='*' || ch=='?' || ch=='|' || ch=='<' || ch=='>' || ch=='"') return false;
    for(const String& part:Split(path,'/',false)) {
        if(part.IsEmpty() || part=="." || part==".." || part.EndsWith(".") || part.EndsWith(" ")) return false;
        String base=ToUpper(GetFileTitle(part));
        if(base=="CON" || base=="NUL" || base=="AUX" || base=="PRN" || (base.GetCount()==4 && (base.StartsWith("COM") || base.StartsWith("LPT")) && base[3]>='1' && base[3]<='9')) return false;
    }
    return true;
}
bool ReadManifest(const String& json,ValueMap& manifest,String& error) {
    auto fail=[&](const String& message) { error=message; return false; };
    if(json.GetCount()>2*1024*1024 || !CheckUtf8(json)) return fail("Setup JSON must be UTF-8 and at most 2 MiB.");
    int depth=0; bool quoted=false,escaped=false;
    for(int ch:json) { if(quoted) { if(escaped) escaped=false; else if(ch=='\\') escaped=true; else if(ch=='"') quoted=false; } else if(ch=='"') quoted=true; else if(ch=='{' || ch=='[') { if(++depth>32) return fail("Setup JSON is nested too deeply."); } else if(ch=='}' || ch==']') { if(--depth<0) return fail("Setup JSON has unbalanced brackets."); } }
    Value v; try { v=ParseJSON(json); } catch(...) { return fail("Setup JSON could not be parsed."); }
    if(!Structure(v) || !Fields(v,"schema_version|product|files|directories|preserve|ports|services|clients")) return fail("Setup contains duplicate or unsupported fields.");
    if(v["schema_version"].Is<bool>() || v["schema_version"]!=1 || !Fields(v["product"],"id|name|version|description") ||
       !Text(v["product"]["id"],64) || !Text(v["product"]["name"],160) || !Text(v["product"]["version"],64)) return fail("Product needs an id, name and version; schema_version must be 1.");
    for(int ch:String(v["product"]["id"])) if(!IsAlNum(ch) && ch!='-' && ch!='_') return fail("Product id may contain only letters, digits, - and _.");
    if(!IsNull(v["product"]["description"]) && !Text(v["product"]["description"],1024)) return fail("Product description must be plain text.");
    if(!v["files"].Is<ValueArray>() || v["files"].GetCount()<1 || v["files"].GetCount()>4096) return fail("Setup must list 1–4096 files explicitly.");
    Index<String> targets;
    for(const Value& file:(ValueArray)v["files"]) {
        if(!Fields(file,"source|target|sha256|policy|platform") || !file["source"].Is<String>() || !RelativePath(String(file["source"])) ||
           !file["target"].Is<String>() || !RelativePath(String(file["target"])) || !Hash(file["sha256"])) return fail("Each file needs safe relative source/target paths and a complete SHA-256.");
        String target=ToLower(String(file["target"]));
        if(target==".upp-installer" || target.StartsWith(".upp-installer/")) return fail("Payload cannot replace installer records.");
        String policy=IsNull(file["policy"])?String("replace"):AsString(file["policy"]);
        if(policy!="replace" && policy!="keep") return fail("File policy must be replace or keep.");
        if(!IsNull(file["platform"]) && file["platform"]!="windows" && file["platform"]!="macos" && file["platform"]!="linux") return fail("File platform must be windows, macos or linux.");
        String key=target+"|"+AsString(file["platform"]);
        if(targets.Find(key)>=0) return fail("Setup lists a duplicate target: "+String(file["target"]));
        targets.Add(key);
    }
    for(const char* key:{"directories","preserve"}) if(!IsNull(v[key])) {
        if(!v[key].Is<ValueArray>() || v[key].GetCount()>256) return fail(String(key)+" must be an array of at most 256 relative paths.");
        for(const Value& path:(ValueArray)v[key]) if(!path.Is<String>() || !RelativePath(String(path)) || ToLower(String(path)).StartsWith(".upp-installer")) return fail(String(key)+" contains an unsafe path.");
    }
    if(!IsNull(v["ports"])) {
        if(!v["ports"].Is<ValueArray>() || v["ports"].GetCount()>32) return fail("ports must contain at most 32 checks.");
        for(const Value& port:(ValueArray)v["ports"]) if(!Fields(port,"name|port|required") || !Text(port["name"],160) || !Integer(port["port"],1,65535) || (!IsNull(port["required"]) && !port["required"].Is<bool>())) return fail("Port checks need a name, port 1–65535 and optional required boolean.");
    }
    for(const char* key:{"services","clients"}) if(!IsNull(v[key])) {
        if(!v[key].Is<ValueArray>() || v[key].GetCount()>16) return fail(String(key)+" must contain at most 16 optional entries.");
        for(const Value& item:(ValueArray)v[key]) {
            if(!Fields(item,String(key)=="clients"?"client|name|program|arguments":"name|program|arguments|port") ||
               !Text(item["name"],160) || !item["program"].Is<String>() || !RelativePath(String(item["program"])) || !Args(item["arguments"])) return fail(String(key)+" needs a name, installed relative program and argument list.");
            if(String(key)=="clients" && item["client"]!="codex" && item["client"]!="opencode") return fail("Supported native client configurations are codex and opencode.");
            if(String(key)=="services" && !IsNull(item["port"]) && !Integer(item["port"],1,65535)) return fail("Service port must be 1–65535.");
            bool listed=false; for(const Value& file:(ValueArray)v["files"]) if(file["target"]==item["program"] && (IsNull(file["platform"]) || file["platform"]==Value(PlatformName()))) listed=true;
            if(!listed) return fail("Optional programs must be included in this platform's verified payload.");
        }
    }
    ValueMap next=v; if(IsNull(next["directories"])) next.Set("directories",ValueArray());
    if(IsNull(next["preserve"])) next.Set("preserve",ValueArray()<<"data");
    for(const char* key:{"ports","services","clients"}) if(IsNull(next[key])) next.Set(key,ValueArray());
    for(const Value& file:(ValueArray)next["files"]) for(const Value& path:(ValueArray)next["preserve"]) {
        String target=ToLower(String(file["target"])),preserve=ToLower(String(path));
        if(target==preserve || target.StartsWith(preserve+"/")) return fail("Payload overlaps preserved user data: "+String(path));
    }
    manifest=pick(next); error.Clear(); return true;
}
bool LoadManifest(const String& path,ValueMap& manifest,String& error) {
    if(!SafePath(path,true)) { error="Setup file is missing or is a linked/unsafe file."; return false; }
    FileIn input(path); if(!input.IsOpen() || input.GetSize()>2*1024*1024) { error="Setup file cannot be read or exceeds 2 MiB."; return false; }
    return ReadManifest(input.Get((int)input.GetSize()),manifest,error);
}
String DefaultDestination(const String& id) {
#ifdef PLATFORM_WIN32
    String base=GetEnv("LOCALAPPDATA"); if(base.IsEmpty()) base=GetHomeDirectory(); return AppendFileName(AppendFileName(base,"Programs"),id);
#elif defined(PLATFORM_OSX)
    return AppendFileName(AppendFileName(GetHomeDirectory(),"Applications"),id);
#else
    return AppendFileName(AppendFileName(GetHomeDirectory(),".local/opt"),id);
#endif
}
bool PortAvailable(int port,String& detail) {
    if(port<1 || port>65535) { detail="Port must be between 1 and 65535."; return false; }
    TcpSocket probe; uint32 loopback=htonl(INADDR_LOOPBACK);
    bool ok=probe.Listen(port,1,false,false,&loopback); detail=ok?String("Available on this computer (not reserved)"):String("Unavailable: ")+probe.GetErrorDesc(); return ok;
}
} }
