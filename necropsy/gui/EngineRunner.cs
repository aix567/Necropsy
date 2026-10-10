using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NecropsyGUI;

public sealed class Finding
{
    [JsonPropertyName("rule")]     public string Rule { get; set; } = "";
    [JsonPropertyName("severity")] public string Severity { get; set; } = "";
    [JsonPropertyName("detail")]   public string Detail { get; set; } = "";
}

public sealed class TriageResult
{
    [JsonPropertyName("path")]                public string Path { get; set; } = "";
    [JsonPropertyName("size")]                public long Size { get; set; }
    [JsonPropertyName("timestamp")]           public long Timestamp { get; set; }
    [JsonPropertyName("module_count")]        public long ModuleCount { get; set; }
    [JsonPropertyName("verdict")]             public string Verdict { get; set; } = "UNKNOWN";
    [JsonPropertyName("score")]               public int Score { get; set; }
    [JsonPropertyName("exception_code")]      public string ExceptionCode { get; set; } = "";
    [JsonPropertyName("exception_name")]      public string ExceptionName { get; set; } = "";
    [JsonPropertyName("access_type")]         public string AccessType { get; set; } = "";
    [JsonPropertyName("faulting_address")]    public string FaultingAddress { get; set; } = "";
    [JsonPropertyName("faulting_module")]     public string FaultingModule { get; set; } = "";
    [JsonPropertyName("faulting_frame")]      public string FaultingFrame { get; set; } = "";
    [JsonPropertyName("instruction_pointer")] public string InstructionPointer { get; set; } = "";
    [JsonPropertyName("stack_pointer")]       public string StackPointer { get; set; } = "";
    [JsonPropertyName("rationale")]           public string Rationale { get; set; } = "";
    [JsonPropertyName("findings")]            public List<Finding> Findings { get; set; } = new();
}

public static class EngineRunner
{
    public static string? FindEngine()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "necropsy-engine.exe"),
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..",
                         "engine", "build", "necropsy-engine.exe"),
            "necropsy-engine.exe",
        };
        foreach (var c in candidates)
            if (File.Exists(c)) return c;
        return null;
    }

    public static TriageResult? Analyze(string enginePath, string dumpPath)
    {
        var psi = new ProcessStartInfo
        {
            FileName = enginePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(dumpPath);
        psi.ArgumentList.Add("--json");

        using var p = Process.Start(psi);
        if (p is null) return null;

        string outJson = p.StandardOutput.ReadToEnd();
        string err = p.StandardError.ReadToEnd();
        p.WaitForExit();

        if (p.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"engine exit {p.ExitCode}: {err}");
        }

        var opts = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        };
        return JsonSerializer.Deserialize<TriageResult>(outJson, opts);
    }
}