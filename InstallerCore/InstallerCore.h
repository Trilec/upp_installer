#ifndef _InstallerCore_InstallerCore_h_
#define _InstallerCore_InstallerCore_h_
#include <Core/Core.h>
#include <functional>
namespace Upp { namespace Installer {
// A manifest describes payload, not code to run during file installation.
// Progress returns false to cancel. Callbacks run on the caller/worker thread.
using Progress = std::function<bool(int64,int64,const String&)>;
struct Plan {
    ValueMap manifest;
    ValueArray files, ports;
    String source, destination, digest;
    int64 bytes=0;
};
bool RelativePath(const String& path);
bool SafePath(const String& path,bool file=false);
bool HashFile(const String& path,String& hash,int64& bytes,String& error,Progress progress={});
bool ReadManifest(const String& json,ValueMap& manifest,String& error);
bool LoadManifest(const String& path,ValueMap& manifest,String& error);
bool PlanInstall(const ValueMap& manifest,const String& source,const String& destination,
                 Plan& plan,String& error,Progress progress={});
bool ApplyInstall(const Plan& plan,ValueMap& receipt,String& error,Progress progress={});
bool RestoreInstall(const String& destination,const String& install_id,ValueMap& receipt,String& error);
ValueArray PendingInstalls(const String& destination,String& error);
bool PortAvailable(int port,String& detail);
String PlatformName();
String DefaultDestination(const String& product_id);
String DefaultClientConfig(const String& client);
// Produce a targeted native client-config edit. No writes in this function.
// Existing conflicting registrations are refused, not overwritten.
bool ClientConfig(const String& client,const String& old_text,const String& name,
                  const String& program,const ValueArray& arguments,String& text,String& error);
bool SaveClientConfig(const String& path,const String& before,const String& after,String& backup,String& error);
bool StartInstalled(const Plan& plan,const String& program,const ValueArray& argv,String& error);
} }
#endif
