public static bool IsProcessElevated {
    get {
        if (IsUacEnabled) {
            IntPtr tokenHandle = IntPtr.Zero;
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_READ, out tokenHandle)) {
                throw new ApplicationException("Could not get process token.  Win32 Error Code: " +
                                               Marshal.GetLastWin32Error());
            }

            try {
                TOKEN_ELEVATION_TYPE elevationResult = TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault;

                int elevationResultSize = Marshal.SizeOf(typeof(TOKEN_ELEVATION_TYPE));
                uint returnedSize = 0;

                IntPtr elevationTypePtr = Marshal.AllocHGlobal(elevationResultSize);
                try {
                    bool success = GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenElevationType,
                                                       elevationTypePtr, (uint)elevationResultSize,
                                                       out returnedSize);
                    if (success) {
                        elevationResult = (TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(elevationTypePtr);
                        bool isProcessAdmin = elevationResult == TOKEN_ELEVATION_TYPE.TokenElevationTypeFull;
                        return isProcessAdmin;
                    } else {
                        throw new ApplicationException("Unable to determine the current elevation.");
                    }
                }
                finally {
                    if (elevationTypePtr != IntPtr.Zero)
                        Marshal.FreeHGlobal(elevationTypePtr);
                }
            }
            finally {
                if (tokenHandle != IntPtr.Zero)
                    CloseHandle(tokenHandle);
            }
        } else {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            bool result = principal.IsInRole(WindowsBuiltInRole.Administrator)
                       || principal.IsInRole(0x200); //Domain Administrator
            return result;
        }
    }
}
}