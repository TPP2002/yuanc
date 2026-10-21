using System.IO;
using System.ServiceProcess;
using WinClient.App.Hosting;

namespace WinClient.App;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        var role = args.FirstOrDefault();
        try
        {
            switch (role)
            {
                case null:
                case "--tray":
                    var app = new App { StartInTray = role == "--tray" };
                    app.InitializeComponent();
                    return app.Run();
                case "--service":
                    using (var service = new ControlService()) ServiceBase.Run(service);
                    return Environment.ExitCode;
                case "--apply-update":
                    return UpdateWindowsHost.ApplyAsync().GetAwaiter().GetResult();
                case "--install":
                case "--uninstall":
                case "--repair":
                    return new InstallerRunner().RunAsync(role).GetAwaiter().GetResult();
                default:
                    Console.Error.WriteLine("无法识别启动参数，请使用客户端快捷方式打开。");
                    return 2;
            }
        }
        catch (Exception)
        {
            if (role == "--service") ControlService.LogFatal();
            else Console.Error.WriteLine("客户端未能启动，请联系管理员。");
            return 1;
        }
    }
}
