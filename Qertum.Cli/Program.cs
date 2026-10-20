using Qertum.Cli;

var parseResult = CliRoot.Build().Parse(args);
return await parseResult.InvokeAsync();
