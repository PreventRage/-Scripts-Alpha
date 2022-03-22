using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;

namespace NyxNUtil_Test {
    [TestClass, System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public class NyxNUtil_UnitTest {
        [TestMethod]
        public void Test_Privilege() {
            Assert.IsTrue((NyxNUtil.TokenAccess.Write | NyxNUtil.TokenAccess.AdjustPrivileges) == NyxNUtil.TokenAccess.Write);

            var PrivilegeName = "SeTakeOwnershipPrivilege";
            var isEnabled = NyxNUtil.HasPrivilege(PrivilegeName: PrivilegeName);
            Assert.IsFalse(isEnabled);
            NyxNUtil.EnablePrivilege(PrivilegeName: PrivilegeName);
            isEnabled = NyxNUtil.HasPrivilege(PrivilegeName: PrivilegeName);
            Assert.IsTrue(isEnabled);

            var PrivilegeId = NyxNUtil.GetPrivilegeId(PrivilegeName: PrivilegeName);
            isEnabled = NyxNUtil.HasPrivilege(PrivilegeId: PrivilegeId);
            Assert.IsFalse(isEnabled);
            NyxNUtil.EnablePrivilege(PrivilegeId: PrivilegeId);
            isEnabled = NyxNUtil.HasPrivilege(PrivilegeId: PrivilegeId);
            Assert.IsTrue(isEnabled);

            // pass both Name and ID (error)
            Assert.ThrowsException<ArgumentException>(
                () => NyxNUtil.HasPrivilege(PrivilegeName: PrivilegeName, PrivilegeId: PrivilegeId)
            );

        }
        [TestMethod]
        public void Test_Uac() {
            var isUacEnabled = NyxNUtil.IsUacEnabled();
            Assert.IsTrue(isUacEnabled);
                // It's been a long time since there were Windows actually allowed UAC to be disabled
        }

        [TestMethod]
        public void Test_GetTokenUser() {
            var sid = NyxNUtil.GetTokenUser();
            var tua = NyxNUtil.LookupAccountSid(sid);
            NyxNUtil.GetTokenElevationType();
        }
    }
}