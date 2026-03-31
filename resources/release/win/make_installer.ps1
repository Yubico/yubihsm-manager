if($args.length -lt 2)
{
    echo "Usage: ./repack_installer.ps1 <WIX_PATH> <MERGE_MODULE_PATH> <VERSION> [<SIGNED_BINARIES_PATH>]"
    echo ""
    echo "This is a script to build an MSI installer for yubihsm manager"
    echo ""
    echo "   WIX_PATH               Absolute path to the directory where WIX Tools binaries (heat.exe, candle.exe and light.exe) are located"
    echo "   MERGE_MODULE_PATH      Absolute path to the redistribution module (tex Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm)"
    echo "   VERSION                Version string to be embedded into the installer (e.g. 1.2.3)"
    echo "   SIGNED_BINARIES_PATH   (Optional) Absolute path to signed binaries. If not spacified, YUBIHSM-MANAGER/resources/release/win/yubihsm-manager is assumed"
    exit
}

$WIX_PATH=$args[0] # Absolute path to the WixTools binaries
$MERGE_MODULE=$args[1] # Absolute path containing Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm
$VERSION=$args[2] # Version string to be embedded into the installer

$WIN_DIR = "$PSScriptRoot"
$SOURCE_DIR="$PSScriptRoot/../../.."

if($args.length -eq 4)
{
    $RELEASE_DIR=$args[3]
}
else
{
    $RELEASE_DIR="$WIN_DIR/yubihsm-manager"
}

Set-PSDebug -Trace 1

# Build MSI
cd $WIN_DIR
$env:PATH += ";$WIX_PATH"
$env:SRCDIR = $RELEASE_DIR
$env:MERGEDPATH = $MERGE_MODULE

heat.exe dir $RELEASE_DIR -out fragment.wxs -gg -scom -srd -sfrag -sreg -dr INSTALLDIR -cg ApplicationFiles -var env.SRCDIR
candle.exe fragment.wxs "yubihsm-manager.wxs" -ext WixUtilExtension  -arch x64
light.exe fragment.wixobj "yubihsm-manager.wixobj" -ext WixUIExtension -ext WixUtilExtension -o "yubihsm-manager-$VERSION.msi"

#cleanup
rm fragment.wxs
rm fragment.wixobj
rm "yubihsm-manager.wixobj"
rm "yubihsm-manager-$VERSION.wixpdb"

Set-PSDebug -Trace 0
