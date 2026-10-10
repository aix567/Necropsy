using System.ComponentModel;
using System.Diagnostics;

namespace NecropsyGUI;

public sealed class MainForm : Form
{
    private readonly ListView _list;
    private readonly TextBox _detail;
    private readonly ToolStripStatusLabel _status;
    private readonly Button _btnAdd;
    private readonly Button _btnRun;
    private readonly Button _btnExport;
    private readonly SplitContainer _split;

    private readonly BindingList<TriageResult> _results = new();

    public MainForm()
    {
        Text = "necropsy — crash triage";
        Width = 1200;
        Height = 720;
        AllowDrop = true;

        _list = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            MultiSelect = true,
            GridLines = true,
        };
        _list.Columns.Add("Score", 60);
        _list.Columns.Add("Verdict", 160);
        _list.Columns.Add("File", 240);
        _list.Columns.Add("Exception", 180);
        _list.Columns.Add("Access", 70);
        _list.Columns.Add("Module", 180);
        _list.Columns.Add("Frame", 220);
        _list.SelectedIndexChanged += List_SelectedIndexChanged;

        _detail = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Font = new Font("Consolas", 9),
            ReadOnly = true,
        };

        _split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterDistance = 400,
        };
        _split.Panel1.Controls.Add(_list);
        _split.Panel2.Controls.Add(_detail);

        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 40,
            Padding = new Padding(6),
        };
        _btnAdd = new Button { Text = "Add dumps…", Width = 110 };
        _btnRun = new Button { Text = "Analyze all", Width = 110 };
        _btnExport = new Button { Text = "Export report…", Width = 130 };
        _btnAdd.Click += BtnAdd_Click;
        _btnRun.Click += BtnRun_Click;
        _btnExport.Click += BtnExport_Click;
        toolbar.Controls.Add(_btnAdd);
        toolbar.Controls.Add(_btnRun);
        toolbar.Controls.Add(_btnExport);

        var status = new StatusStrip();
        _status = new ToolStripStatusLabel("ready");
        status.Items.Add(_status);

        Controls.Add(_split);
        Controls.Add(toolbar);
        Controls.Add(status);

        DragEnter += (s, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true)
                e.Effect = DragDropEffects.Copy;
        };
        DragDrop += (s, e) =>
        {
            var files = e.Data?.GetData(DataFormats.FileDrop) as string[];
            if (files is null) return;
            foreach (var f in files) QueueFile(f);
        };
    }

    private readonly List<string> _queue = new();

    private void QueueFile(string path)
    {
        if (Directory.Exists(path))
        {
            foreach (var f in Directory.EnumerateFiles(path, "*.dmp"))
                _queue.Add(f);
        }
        else if (File.Exists(path) &&
                 path.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase))
        {
            _queue.Add(path);
        }
        _status.Text = $"{_queue.Count} dumps queued";
    }

    private void BtnAdd_Click(object? sender, EventArgs e)
    {
        using var ofd = new OpenFileDialog
        {
            Multiselect = true,
            Filter = "Crash dumps (*.dmp)|*.dmp|All files (*.*)|*.*",
        };
        if (ofd.ShowDialog() == DialogResult.OK)
            foreach (var f in ofd.FileNames) QueueFile(f);
    }

    private async void BtnRun_Click(object? sender, EventArgs e)
    {
        var engine = EngineRunner.FindEngine();
        if (engine is null)
        {
            MessageBox.Show(
                "necropsy-engine.exe not found.\n\n" +
                "Build the C++ engine first, or place the exe next to this GUI.",
                "engine missing", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
        if (_queue.Count == 0)
        {
            MessageBox.Show("No dumps queued. Drop .dmp files or use Add.",
                "empty", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        _btnRun.Enabled = false;
        _list.Items.Clear();
        _results.Clear();

        int i = 0;
        int total = _queue.Count;
        var sw = Stopwatch.StartNew();

        foreach (var path in _queue.ToList())
        {
            i++;
            _status.Text = $"analyzing {i}/{total}: {Path.GetFileName(path)}";
            try
            {
                var r = await Task.Run(() => EngineRunner.Analyze(engine, path));
                if (r is null) continue;
                _results.Add(r);
                var item = new ListViewItem(new[]
                {
                    r.Score.ToString(),
                    r.Verdict,
                    Path.GetFileName(r.Path),
                    r.ExceptionName,
                    r.AccessType,
                    r.FaultingModule,
                    r.FaultingFrame,
                })
                { Tag = r };
                if (r.Verdict == "EXPLOITABLE")
                    item.BackColor = Color.FromArgb(255, 220, 220);
                else if (r.Verdict == "PROBABLY_EXPLOITABLE")
                    item.BackColor = Color.FromArgb(255, 245, 220);
                _list.Items.Add(item);
            }
            catch (Exception ex)
            {
                _status.Text = $"failed: {Path.GetFileName(path)} — {ex.Message}";
            }
        }

        sw.Stop();
        _status.Text = $"done — {_results.Count}/{total} in {sw.ElapsedMilliseconds} ms";
        _btnRun.Enabled = true;
    }

    private void List_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (_list.SelectedItems.Count == 0) { _detail.Text = ""; return; }
        var r = _list.SelectedItems[0].Tag as TriageResult;
        if (r is null) return;
        _detail.Text = FormatDetail(r);
    }

    private static string FormatDetail(TriageResult r)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"path:        {r.Path}");
        sb.AppendLine($"size:        {r.Size} bytes");
        sb.AppendLine($"modules:     {r.ModuleCount}");
        sb.AppendLine($"verdict:     {r.Verdict}  (score {r.Score})");
        sb.AppendLine();
        sb.AppendLine($"exception:   {r.ExceptionCode}  ({r.ExceptionName})");
        sb.AppendLine($"access:      {r.AccessType}");
        sb.AppendLine($"address:     {r.FaultingAddress}");
        sb.AppendLine($"module:      {r.FaultingModule}");
        sb.AppendLine($"frame:       {r.FaultingFrame}");
        sb.AppendLine($"rip:         {r.InstructionPointer}");
        sb.AppendLine($"rsp:         {r.StackPointer}");
        sb.AppendLine();
        sb.AppendLine("findings:");
        foreach (var f in r.Findings)
            sb.AppendLine($"  [{f.Severity,-8}] {f.Rule,-20} {f.Detail}");
        return sb.ToString();
    }

    private void BtnExport_Click(object? sender, EventArgs e)
    {
        if (_results.Count == 0)
        {
            MessageBox.Show("Nothing to export.", "empty");
            return;
        }
        using var sfd = new SaveFileDialog
        {
            Filter = "JSON (*.json)|*.json|CSV (*.csv)|*.csv|Text (*.txt)|*.txt",
            FileName = "necropsy_report.json",
        };
        if (sfd.ShowDialog() != DialogResult.OK) return;
        var path = sfd.FileName;

        if (path.EndsWith(".json"))
        {
            var opts = new System.Text.Json.JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(path,
                System.Text.Json.JsonSerializer.Serialize(_results, opts));
        }
        else if (path.EndsWith(".csv"))
        {
            using var w = new StreamWriter(path);
            w.WriteLine("score,verdict,file,exception,access,module,frame");
            foreach (var r in _results)
                w.WriteLine($"{r.Score},{r.Verdict},{Path.GetFileName(r.Path)}," +
                            $"{r.ExceptionName},{r.AccessType},{r.FaultingModule}," +
                            $"{r.FaultingFrame}");
        }
        else
        {
            using var w = new StreamWriter(path);
            foreach (var r in _results)
            {
                w.WriteLine(FormatDetail(r));
                w.WriteLine(new string('-', 80));
            }
        }
        _status.Text = $"exported: {path}";
    }
}