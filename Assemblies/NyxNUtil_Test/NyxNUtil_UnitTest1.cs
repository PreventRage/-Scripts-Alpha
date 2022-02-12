using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;

namespace NyxNUtil_Test {
    [TestClass]
    public class NyxNUtil_UnitTest1 {
        [TestMethod]
        public void Test_Privilege_1() {
            string PrivilegeName = "SeTakeOwnershipPrivilege";
            bool isEnabled = NyxNUtil.HasPrivilege(PrivilegeName: PrivilegeName);
            Assert.IsFalse(isEnabled);
            NyxNUtil.EnablePrivilege(PrivilegeName: PrivilegeName);
            isEnabled = NyxNUtil.HasPrivilege(PrivilegeName: PrivilegeName);
            Assert.IsTrue(isEnabled);
        }
        [TestMethod]
        public void Test_Uac_1() {
            bool isUacEnabled = NyxNUtil.IsUacEnabled;
            Assert.IsTrue(isUacEnabled);
        }

    }
}