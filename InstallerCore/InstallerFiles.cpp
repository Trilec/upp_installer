#include "InstallerCore.h"
#ifdef PLATFORM_WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#endif
namespace Upp { namespace Installer {
namespace {
String Join(const String& root,const String& path) { return AppendFileName(root,path); }
String Key(const String& path) { String s=ToLower(NormalizePath(path)); s.Replace("\\","/"); while(s.EndsWith("/")) s.Trim(s.GetCount()-1); return s; }
bool Nested(const String& a,const String& b) { return a==b || a.StartsWith(b+"/"); }
bool MoveAtomic(const String& from,const String& to,String& error) {
#ifdef PLATFORM_WIN32
    if(MoveFileExW(ToSystemCharsetW(from),ToSystemCharsetW(to),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) return true;
    error="Windows could not replace "+to+" (error "+AsString((int)GetLastError())+"). Close applications using it, then retry.";
#else
    if(rename(~from,~to)==0) return true;
    error="Could not replace "+to+": "+String(strerror(errno));
#endif
    return false;
}
bool SaveRecord(const String& path,const Value& record,String& error) {
    String temporary=path+"."+AsString(Uuid::Create())+".tmp";
    if(!SafePath(path) || !SaveFile(temporary,AsJSON(record,true))) { error="Cannot save installation record."; return false; }
    if(!MoveAtomic(temporary,path,error)) { FileDelete(temporary); return false; }
    return true;
}
bool CopyVerified(const String& source,const String& target,const String& expected,String& error,Progress progress) {
    if(!SafePath(source,true) || !SafePath(target) || !RealizeDirectory(GetFileFolder(target))) { error="Unsafe or unavailable copy path."; return false; }
    FileIn input(source); if(!input.IsOpen()) { error="Cannot read "+source; return false; }
    int64 size=input.GetSize(),done=0; FileOut output(target);
    if(!output.IsOpen()) { error="Cannot create staging file "+target; return false; }
    Sha256Stream hash; Buffer<byte> buffer(262144);
    while(done<size) {
        if(progress && !progress(done,size,GetFileName(source))) { error="Cancelled"; output.Close(); FileDelete(target); return false; }
        int n=input.Get(~buffer,(int)min<int64>(262144,size-done));
        if(n<=0 || input.IsError()) { error="Payload changed or could not be read: "+source; output.Close(); FileDelete(target); return false; }
        hash.Put(~buffer,n); output.Put(~buffer,n); done+=n;
        if(output.IsError()) { error="Writing failed: "+target; output.Close(); FileDelete(target); return false; }
    }
    output.Close(); input.Close();
    if(hash.FinishString()!=ToLower(expected)) { error="Payload SHA-256 changed: "+source; FileDelete(target); return false; }
#ifndef PLATFORM_WIN32
    struct stat info{}; if(stat(~source,&info)!=0 || chmod(~target,info.st_mode&0777)!=0) { error="Cannot retain program permissions."; return false; }
#endif
    String actual; int64 bytes;
    if(!HashFile(target,actual,bytes,error) || actual!=ToLower(expected) || bytes!=done) { error="Staged file verification failed: "+target; return false; }
    return true;
}
class InstallLock : NoCopy {
#ifdef PLATFORM_WIN32
    HANDLE handle=INVALID_HANDLE_VALUE;
#else
    int handle=-1;
#endif
public:
    bool Acquire(const String& path) {
        if(!SafePath(path)) return false;
#ifdef PLATFORM_WIN32
        handle=CreateFileW(ToSystemCharsetW(path),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        return handle!=INVALID_HANDLE_VALUE;
#else
        handle=open(~path,O_RDWR|O_CREAT|O_NOFOLLOW,0600);
        if(handle<0) return false;
        struct flock lock{}; lock.l_type=F_WRLCK; lock.l_whence=SEEK_SET; return fcntl(handle,F_SETLK,&lock)==0;
#endif
    }
    ~InstallLock() {
#ifdef PLATFORM_WIN32
        if(handle!=INVALID_HANDLE_VALUE) CloseHandle(handle);
#else
        if(handle>=0) close(handle);
#endif
    }
};
bool Current(const String& path,const String& expected,String& error) {
    if(expected.IsEmpty()) { if(!FileExists(path) && !DirectoryExists(path)) return true; error="Destination appeared since review: "+path; return false; }
    String actual; int64 bytes; if(!HashFile(path,actual,bytes,error)) return false;
    if(actual!=expected) { error="Destination changed since review: "+path; return false; } return true;
}
}
bool SafePath(const String& path,bool file) {
    if(!IsFullPath(path) || path.StartsWith("\\\\?\\") || path.StartsWith("\\\\.\\")) return false;
    String current=NormalizePath(path); bool first=true;
    for(int n=0;n<512;++n) {
#ifdef PLATFORM_WIN32
        DWORD attributes=GetFileAttributesW(ToSystemCharsetW(current));
        if(attributes!=INVALID_FILE_ATTRIBUTES && (attributes&FILE_ATTRIBUTE_REPARSE_POINT)) return false;
        if(first && file && (attributes==INVALID_FILE_ATTRIBUTES || (attributes&FILE_ATTRIBUTE_DIRECTORY))) return false;
        if(first && file) { HANDLE h=CreateFileW(ToSystemCharsetW(current),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr); if(h==INVALID_HANDLE_VALUE) return false; BY_HANDLE_FILE_INFORMATION info{}; bool single=GetFileInformationByHandle(h,&info)&&info.nNumberOfLinks==1; CloseHandle(h); if(!single) return false; }
#else
        struct stat info{}; int result=lstat(~current,&info);
        if(result==0 && S_ISLNK(info.st_mode)) return false;
        if(first && file && (result!=0 || !S_ISREG(info.st_mode) || info.st_nlink!=1)) return false;
#endif
        String parent=GetFileFolder(current); if(parent==current || parent.IsEmpty()) return true; current=parent; first=false;
    }
    return false;
}
bool HashFile(const String& path,String& hash,int64& bytes,String& error,Progress progress) {
    hash.Clear(); bytes=0;
    if(!SafePath(path,true)) { error="Missing, linked or unreadable file: "+path; return false; }
    FileIn input(path); if(!input.IsOpen()) { error="Cannot read "+path; return false; }
    int64 size=input.GetSize(); FileTime modified=GetFileTime(path); Sha256Stream digest; Buffer<byte> buffer(262144);
    while(bytes<size) {
        if(progress && !progress(bytes,size,GetFileName(path))) { error="Cancelled"; return false; }
        int n=input.Get(~buffer,(int)min<int64>(262144,size-bytes)); if(n<=0 || input.IsError()) { error="File changed or read failed: "+path; return false; }
        digest.Put(~buffer,n); bytes+=n;
    }
    if(GetFileLength(path)!=size || GetFileTime(path)!=modified) { error="File changed while checking: "+path; return false; }
    hash=digest.FinishString(); error.Clear(); return true;
}
ValueArray PendingInstalls(const String& destination,String& error) {
    ValueArray result; error.Clear(); String directory=Join(destination,".upp-installer"); if(!DirectoryExists(directory)) return result;
    if(!SafePath(directory)) { error="Installation history is linked or unsafe."; return result; }
    int count=0; for(FindFile entry(Join(directory,"*"));entry;++entry) if(entry.IsFolder() && entry.GetName()!="." && entry.GetName()!="..") {
        if(++count>1024) { error="Installation history exceeds 1024 records. Review archived history before installing."; return result; }
        String path=Join(Join(directory,entry.GetName()),"receipt.json");
        if(!FileExists(path)) continue;
        if(!SafePath(path,true) || GetFileLength(path)>2*1024*1024) { error="Unsafe installation record: "+path; return result; }
        Value record; try { record=ParseJSON(LoadFile(path)); } catch(...) {}
        if(!record.Is<ValueMap>()) { error="Invalid installation record: "+path; return result; }
        if(record["state"]!="installed" && record["state"]!="restored") result.Add(ValueMap()("id",entry.GetName())("state",record["state"])("record",path));
    }
    return result;
}
bool PlanInstall(const ValueMap& input,const String& source,const String& destination,Plan& plan,String& error,Progress progress) {
    ValueMap manifest; if(!ReadManifest(AsJSON(input,false),manifest,error)) return false;
    if(!IsFullPath(source) || !DirectoryExists(source) || !SafePath(source) || !IsFullPath(destination) || !SafePath(destination)) { error="Choose existing, absolute payload and absolute destination folders without links."; return false; }
    String src=Key(source),dst=Key(destination);
    if(Nested(src,dst) || Nested(dst,src) || Key(GetHomeDirectory())==dst || Key(GetFileFolder(destination))==dst) { error="Choose a dedicated destination outside the payload, not your home or a drive root."; return false; }
    ValueArray pending=PendingInstalls(destination,error); if(!error.IsEmpty()) return false;
    if(!pending.IsEmpty()) { error="An interrupted installation needs recovery before another install: "+AsString(pending[0]["record"]); return false; }
    Plan next; next.manifest=manifest; next.source=NormalizePath(source); next.destination=NormalizePath(destination); Index<String> selected;
    ValueArray specs=manifest["files"];
    for(int i=0;i<specs.GetCount();++i) {
        Value spec=specs[i]; if(!IsNull(spec["platform"]) && spec["platform"]!=Value(PlatformName())) continue;
        String relative=spec["target"]; if(selected.Find(ToLower(relative))>=0) { error="Multiple payloads target "+relative+" on this platform."; return false; } selected.Add(ToLower(relative));
        String from=Join(next.source,AsString(spec["source"])),to=Join(next.destination,relative),hash; int64 size;
        auto step=[&](int64,int64,const String&) { return !progress || progress(i,specs.GetCount(),"Verify "+relative); };
        if(!HashFile(from,hash,size,error,step)) return false;
        if(hash!=ToLower(AsString(spec["sha256"]))) { error="Payload hash does not match setup JSON: "+AsString(spec["source"]); return false; }
        if(size>int64(8)*1024*1024*1024 || next.bytes>int64(32)*1024*1024*1024-size) { error="Payload exceeds 8 GiB/file or 32 GiB/install."; return false; }
        if(!SafePath(to) || DirectoryExists(to)) { error="Unsafe destination file: "+relative; return false; }
        String before; int64 previous=0;
        if(FileExists(to) && !HashFile(to,before,previous,error)) return false;
        bool keep=spec["policy"]=="keep" && !before.IsEmpty();
        ValueMap row; row.Add("source",spec["source"]); row.Add("target",relative); row.Add("sha256",hash); row.Add("before",before); row.Add("bytes",size); row.Add("action",keep?"keep":hash==before?"unchanged":before.IsEmpty()?"create":"replace"); next.files.Add(row);
        if(!keep && hash!=before) next.bytes+=size;
    }
    if(next.files.IsEmpty()) { error="Setup has no files for "+PlatformName()+"."; return false; }
    for(const Value& port:(ValueArray)manifest["ports"]) {
        String detail; bool available=PortAvailable((int)port["port"],detail); ValueMap row=port; row.Set("available",available); row.Set("detail",detail); next.ports.Add(row);
        if(port["required"]==true && !available) { error="Required port "+AsString(port["port"])+" ("+AsString(port["name"])+") is unavailable. "+detail; return false; }
    }
    next.digest=SHA256String(AsJSON(next.files,false)+next.source+next.destination+AsJSON(manifest,false));
    plan=pick(next); error.Clear(); return true;
}
bool RestoreInstall(const String& destination,const String& id,ValueMap& receipt,String& error) {
    if(!RelativePath(id) || id.Find('/')>=0 || !SafePath(destination)) { error="Invalid recovery location."; return false; }
    String history=Join(destination,".upp-installer"),directory=Join(history,id),path=Join(directory,"receipt.json");
    if(!SafePath(path,true) || GetFileLength(path)>2*1024*1024) { error="Missing or unsafe recovery record."; return false; }
    InstallLock lock; if(!lock.Acquire(Join(history,"install.lock"))) { error="Another installer is using this destination."; return false; }
    Value record; try { record=ParseJSON(LoadFile(path)); } catch(...) {}
    if(!record.Is<ValueMap>() || record["schema_version"]!=1 || Key(AsString(record["destination"]))!=Key(destination) || record["install_id"]!=Value(id) || !record["files"].Is<ValueArray>() || record["files"].GetCount()>4096) { error="Recovery record does not match this destination."; return false; }
    bool restored=true; ValueArray files=record["files"];
    for(int i=files.GetCount()-1;i>=0;--i) {
        Value file=files[i]; String relative=AsString(file["target"]);
        if(!RelativePath(relative) || ToLower(relative).StartsWith(".upp-installer")) { restored=false; error="Unsafe recovery target."; break; }
        if(file["action"]=="keep" || file["action"]=="unchanged") continue;
        String target=Join(destination,relative),before=AsString(file["before"]),after=AsString(file["sha256"]),current,why; int64 bytes;
        if(!FileExists(target) && before.IsEmpty()) continue;
        if(!HashFile(target,current,bytes,why)) { restored=false; error=why; continue; }
        if(current==before) continue;
        if(current!=after) { restored=false; error="Recovery preserved a file changed since installation: "+relative; continue; }
        if(before.IsEmpty()) { if(!FileDelete(target)) { restored=false; error="Cannot remove newly installed file: "+relative; } }
        else {
            String backup=Join(Join(directory,"backup"),relative),temp=Join(directory,"restore-"+AsString(i));
            if(!CopyVerified(backup,temp,before,why,{}) || !MoveAtomic(temp,target,why)) { restored=false; error=why; }
        }
    }
    receipt=record; receipt.Set("state",restored?"restored":"recovery_required"); receipt.Set("restoration_verified",restored); receipt.Set("message",restored?String("Previous file contents restored. User data and unrelated files were preserved."):error);
    if(!SaveRecord(path,receipt,error)) return false;
    return restored;
}
bool ApplyInstall(const Plan& plan,ValueMap& receipt,String& error,Progress progress) {
    if(plan.digest!=SHA256String(AsJSON(plan.files,false)+plan.source+plan.destination+AsJSON(plan.manifest,false))) { error="Installation plan changed; review again."; return false; }
    Plan fresh; if(!PlanInstall(plan.manifest,plan.source,plan.destination,fresh,error)) return false;
    if(fresh.digest!=plan.digest) { error="Payload or destination changed since review; review again."; return false; }
    String history=Join(plan.destination,".upp-installer");
    if(!RealizeDirectory(history) || !SafePath(history)) { error="Cannot create installer history."; return false; }
    String id=AsString(Uuid::Create()),directory=Join(history,id),path=Join(directory,"receipt.json");
    ValueMap record; record.Add("schema_version",1); record.Add("install_id",id); record.Add("destination",plan.destination); record.Add("product",plan.manifest["product"]); record.Add("files",plan.files); record.Add("state","preparing"); record.Add("created_at",AsString(GetUtcTime()));
    {
        InstallLock lock; if(!lock.Acquire(Join(history,"install.lock"))) { error="Another installer is using this destination."; return false; }
        if(!RealizeDirectory(directory) || !SaveRecord(path,record,error)) return false;
        int64 done=0;
        for(const Value& file:plan.files) {
            String action=file["action"],relative=file["target"]; if(action=="keep" || action=="unchanged") continue;
            auto step=[&](int64 actual,int64,const String&) { return !progress || progress(done+actual,max<int64>(1,plan.bytes),"Prepare "+relative); };
            if(!CopyVerified(Join(plan.source,AsString(file["source"])),Join(Join(directory,"stage"),relative),AsString(file["sha256"]),error,step)) break;
            String before=file["before"];
            if(!before.IsEmpty() && !CopyVerified(Join(plan.destination,relative),Join(Join(directory,"backup"),relative),before,error,{})) break;
            done+=(int64)file["bytes"];
        }
        if(error.IsEmpty()) {
            record.Set("state","applying");
            if(SaveRecord(path,record,error)) {
                for(const Value& dir:(ValueArray)plan.manifest["directories"]) if(!SafePath(Join(plan.destination,AsString(dir))) || !RealizeDirectory(Join(plan.destination,AsString(dir)))) { error="Cannot create directory: "+AsString(dir); break; }
                int n=0; for(const Value& file:plan.files) {
                    if(!error.IsEmpty()) break;
                    String action=file["action"],relative=file["target"]; if(action=="keep" || action=="unchanged") continue;
                    if(progress && !progress(n++,plan.files.GetCount(),"Install "+relative)) { error="Cancelled"; break; }
                    String target=Join(plan.destination,relative);
                    if(!Current(target,AsString(file["before"]),error) || !SafePath(target) || !RealizeDirectory(GetFileFolder(target)) || !MoveAtomic(Join(Join(directory,"stage"),relative),target,error)) { if(error.IsEmpty()) error="Cannot publish "+relative; break; }
                }
            }
        }
        if(error.IsEmpty()) for(const Value& file:plan.files) {
            if(file["action"]=="keep") continue;
            if(!Current(Join(plan.destination,AsString(file["target"])),AsString(file["sha256"]),error)) break;
        }
        if(error.IsEmpty()) { record.Set("state","installed"); record.Set("completed_at",AsString(GetUtcTime())); if(SaveRecord(path,record,error)) { receipt=record; if(progress) progress(1,1,"Installed and verified"); return true; } }
    }
    String failure=error,restore_error; ValueMap restored;
    bool ok=RestoreInstall(plan.destination,id,restored,restore_error);
    receipt=restored; receipt.Set("installation_error",failure); error=failure+(ok?String("\nPrevious files restored."):String("\nRecovery needs attention: ")+restore_error);
    return false;
}
bool StartInstalled(const Plan& plan,const String& program,const ValueArray& argv,String& error) {
    if(!RelativePath(program)) { error="Invalid installed program path."; return false; }
    String expected; for(const Value& file:plan.files) if(file["target"]==Value(program)) expected=AsString(file["sha256"]);
    String path=Join(plan.destination,program),hash; int64 bytes;
    if(expected.IsEmpty() || !HashFile(path,hash,bytes,error) || hash!=expected) { error="Installed program has not passed verification."; return false; }
    Vector<String> arguments; for(const Value& arg:argv) { if(!arg.Is<String>()) { error="Invalid program argument."; return false; } String value=arg; value.Replace("${destination}",plan.destination); arguments.Add(value); }
    LocalProcess process; if(!process.Start(~path,arguments,nullptr,~plan.destination)) { error="Could not start the installed program."; return false; } process.Detach(); error.Clear(); return true;
}
} }
