package sysio

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
	"github.com/spf13/afero"
)

func TestMain(m *testing.M) {

	// Disable log generation during UT.
	log.SetOutput(ioutil.Discard)

	m.Run()
}

func Test_ioFileService_NewIOnode(t *testing.T) {

	// Test definition.
	type args struct {
		n    string
		p    string
		attr os.FileMode
	}
	tests := []struct {
		name string
		s    domain.IOService
		args args
		want domain.IOnode
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.NewIOnode(tt.args.n, tt.args.p, tt.args.attr); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ioFileService.NewIOnode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Refer to IOnodeFile.Open() for more thorough testing.
func Test_ioFileService_OpenNode(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)

	// Required IOSservice and associated IOnode.
	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)

	// Test definition.
	type args struct {
		i domain.IOnode
	}
	tests := []struct {
		name    string
		s       domain.IOService
		args    args
		wantErr bool
	}{
		{"1", ios, args{i1}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.OpenNode(tt.args.i); (err != nil) != tt.wantErr {
				t.Errorf("ioFileService.OpenNode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Refer to IOnodeFile.Read() for more thorough testing.
func Test_ioFileService_ReadNode(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)

	// Required IOSservice and associated IOnode.
	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i1Buff = make([]byte, 3)

	// Open newly created files.
	_ = i1.Open()

	// Test definition.
	type args struct {
		i domain.IOnode
		p []byte
	}
	tests := []struct {
		name    string
		s       domain.IOService
		args    args
		want    int
		wantErr bool
	}{
		{"1", ios, args{i1, i1Buff}, 3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.ReadNode(tt.args.i, tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("ioFileService.ReadNode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ioFileService.ReadNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Refer to IOnodeFile.Write() for more thorough testing.
func Test_ioFileService_WriteNode(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)

	// Required IOSservice and associated IOnode.
	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i1Buff = []byte("456")

	// Set openflags and open the new created file.
	i1.SetOpenFlags(syscall.O_WRONLY)

	// Open newly created files.
	_ = i1.Open()

	// Test definition.
	type args struct {
		i domain.IOnode
		p []byte
	}
	tests := []struct {
		name    string
		s       domain.IOService
		args    args
		want    int
		wantErr bool
	}{
		{"1", ios, args{i1, i1Buff}, 3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.WriteNode(tt.args.i, tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("ioFileService.WriteNode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ioFileService.WriteNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Refer to IOnodeFile.Close() for more thorough testing.
func Test_ioFileService_CloseNode(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)

	// Required IOSservice and associated IOnode.
	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)

	// Open newly created files.
	_ = i1.Open()

	// Test definition.
	type args struct {
		i domain.IOnode
	}
	tests := []struct {
		name    string
		s       domain.IOService
		args    args
		wantErr bool
	}{
		{"1", ios, args{i1}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.CloseNode(tt.args.i); (err != nil) != tt.wantErr {
				t.Errorf("ioFileService.CloseNode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Refer to IOnodeFile.ReadAt() for more thorough testing.
func Test_ioFileService_ReadAtNode(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)

	// Required IOSservice and associated IOnode.
	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i1Buff = make([]byte, 3)

	// Open newly created files.
	_ = i1.Open()

	// Test definition.
	type args struct {
		i   domain.IOnode
		p   []byte
		off int64
	}
	tests := []struct {
		name    string
		s       domain.IOService
		args    args
		want    int
		wantErr bool
	}{
		{"1", ios, args{i1, i1Buff, 0}, 3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.ReadAtNode(tt.args.i, tt.args.p, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("ioFileService.ReadAtNode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ioFileService.ReadAtNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Refer to IOnodeFile.ReadDirAll() for more thorough testing.
func Test_ioFileService_ReadDirAllNode(t *testing.T) {

	// Test definition.
	type args struct {
		i domain.IOnode
	}
	tests := []struct {
		name    string
		s       domain.IOService
		args    args
		want    []os.FileInfo
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.ReadDirAllNode(tt.args.i)
			if (err != nil) != tt.wantErr {
				t.Errorf("ioFileService.ReadDirAllNode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ioFileService.ReadDirAllNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Refer to IOnodeFile.ReadLine() for more thorough testing.
func Test_ioFileService_ReadLineNode(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)

	// Required IOSservice and associated IOnode.
	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)

	// Open newly created file.
	_ = i1.Open()

	// Test definition.
	type args struct {
		i domain.IOnode
	}
	tests := []struct {
		name string
		s    domain.IOService
		args args
		want string
	}{
		{"1", ios, args{i1}, "123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.ReadLineNode(tt.args.i); got != tt.want {
				t.Errorf("ioFileService.ReadLineNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Refer to IOnodeFile.Stat() for more thorough testing.
func Test_ioFileService_StatNode(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)

	// Required IOSservice and associated IOnode.
	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)

	var expected1 = domain.FileInfo{Fname: "uptime1", Fmode: 0644}

	// Test definition.
	type args struct {
		i domain.IOnode
	}
	tests := []struct {
		name    string
		s       domain.IOService
		args    args
		want    os.FileInfo
		wantErr bool
	}{
		{"1", ios, args{i1}, expected1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.StatNode(tt.args.i)
			if (err != nil) != tt.wantErr {
				t.Errorf("ioFileService.StatNode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify that received os.FileInfo meets our expectations.
			if got.Name() != tt.want.Name() || got.Mode() != tt.want.Mode() {
				t.Errorf("received Name() = %v, Mode() = %v, want Name() = %v, Mode = %v",
					got.Name(), got.Mode(), tt.want.Name(), tt.want.Mode())
			}
		})
	}
}

// Refer to IOnodeFile.SeekReset() for more thorough testing.
func Test_ioFileService_SeekResetNode(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)

	// Required IOSservice and associated IOnode.
	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)

	// Open newly created file.
	_ = i1.Open()

	// Test definition.
	type args struct {
		i domain.IOnode
	}
	tests := []struct {
		name    string
		s       domain.IOService
		args    args
		want    int64
		wantErr bool
	}{
		{"1", ios, args{i1}, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.SeekResetNode(tt.args.i)
			if (err != nil) != tt.wantErr {
				t.Errorf("ioFileService.SeekResetNode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ioFileService.SeekResetNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// To be skipped for now. Refer to IOnodeFile.PidNsInode() for more details.
func Test_ioFileService_PidNsInode(t *testing.T) {

	// Skipping this one for now.
	t.Skip("Skipping IOnodeService.PidNsInode() for now")

	// Test definition.
	type args struct {
		i domain.IOnode
	}
	tests := []struct {
		name    string
		s       domain.IOService
		args    args
		want    domain.Inode
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.PidNsInode(tt.args.i)
			if (err != nil) != tt.wantErr {
				t.Errorf("ioFileService.PidNsInode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ioFileService.PidNsInode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Refer to IOnodeFile.PathNode() for more thorough testing.
func Test_ioFileService_PathNode(t *testing.T) {

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)

	// Test definition.
	type args struct {
		i domain.IOnode
	}
	tests := []struct {
		name string
		s    domain.IOService
		args args
		want string
	}{
		{"1", ios, args{i1}, "/proc/uptime1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.PathNode(tt.args.i); got != tt.want {
				t.Errorf("ioFileService.PathNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIOnodeFile_Open(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i2 = ios.NewIOnode("uptime2", "/proc/uptime2", 0644)

	// Test definition.
	tests := []struct {
		name    string
		i       domain.IOnode
		wantErr bool
	}{
		// Open existing file.
		{"1", i1, false},

		// Open non-existing file.
		{"2", i2, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.i.Open(); (err != nil) != tt.wantErr {
				t.Errorf("IOnodeFile.Open() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIOnodeFile_Read(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime2", []byte("123\n456\n789"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime3", []byte("123\n456"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime4", []byte("123\n456"), 0644)

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i2 = ios.NewIOnode("uptime2", "/proc/uptime2", 0644)
	var i3 = ios.NewIOnode("uptime3", "/proc/uptime3", 0644)
	var i4 = ios.NewIOnode("uptime4", "/proc/uptime4", 0644)

	var i1Buff = make([]byte, 3)
	var i2Buff = make([]byte, 11)
	var i3Buff = make([]byte, 3)

	// Open newly created files.
	_ = i1.Open()
	_ = i2.Open()
	_ = i3.Open()

	// Test definition.
	type args struct {
		p []byte
	}
	tests := []struct {
		name    string
		i       domain.IOnode
		args    args
		wantN   int
		wantErr bool
	}{
		// Read 3 characters from a existing file.
		{"1", i1, args{i1Buff}, 3, false},

		// Read all content from multi-line file.
		{"2", i2, args{i2Buff}, 11, false},

		// Read all content from multi-line file into a buff with a size not
		// large enough to accommodate all file content. Operation succeed if enough
		// characters are read from file -- i.e. len(buf).
		{"3", i3, args{i3Buff}, 3, false},

		// Read on un-opened file. Error expected.
		{"4", i4, args{i3Buff}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotN, err := tt.i.Read(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("IOnodeFile.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("IOnodeFile.Read() = %v, want %v", gotN, tt.wantN)
			}

			// Return at this point if an error is expected. Notice that
			// subsequent steps attempt to read from files again, so better
			// return here in these cases.
			if tt.wantErr {
				return
			}

			// Let's also ensure that the content of the original file and the
			// result-buffer is fully matching.
			content, erri := afero.ReadFile(AppFs, tt.i.Path())
			if erri != nil {
				t.Errorf("IOnodeFile.Read() error = %v, couldn't read back from file",
					erri)
				return
			}
			if string(content[:tt.wantN]) != string(tt.args.p) {
				t.Errorf("IOnodeFile.Read() content = %v, want %v",
					string(content), string(tt.args.p))
				return
			}
		})
	}
}

func TestIOnodeFile_Write(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime2", []byte("123"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime3", []byte("123"), 0644)

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0)
	var i2 = ios.NewIOnode("uptime2", "/proc/uptime2", 0)
	var i3 = ios.NewIOnode("uptime3", "/proc/uptime3", 0)
	//var i3 = ios.NewIOnode("uptime3", "/proc/uptime3", 0)
	var i1Buff = []byte("456")
	var i2Buff = []byte("abcdef\nghijk")
	var i3Buff = []byte("123")

	// Set openflags and open the new created files.
	i1.SetOpenFlags(syscall.O_WRONLY)
	i2.SetOpenFlags(syscall.O_WRONLY)
	i3.SetOpenFlags(syscall.O_WRONLY)
	_ = i1.Open()
	_ = i2.Open()

	// Test definition.
	type args struct {
		p []byte
	}
	tests := []struct {
		name    string
		i       domain.IOnode
		args    args
		wantN   int
		wantErr bool
	}{
		// Write 3 characters over existing file. Verify that original content
		// is wiped out.
		{"1", i1, args{i1Buff}, 3, false},

		// Writing over a non-existing file -- no matching entry in afero-fs.
		// File should be created with the expected content.
		{"2", i2, args{i2Buff}, 12, false},

		// Write on un-opened file. Error expected.
		{"3", i3, args{i3Buff}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotN, err := tt.i.Write(tt.args.p)

			if (err != nil) != tt.wantErr {
				t.Errorf("IOnodeFile.Write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("IOnodeFile.Write() = %v, want %v", gotN, tt.wantN)
			}

			// Let's also ensure that the content of the original buffer and the
			// destination file is fully matching.
			content, erri := afero.ReadFile(AppFs, tt.i.Path())
			if erri != nil {
				t.Errorf("IOnodeFile.Write() error = %v, couldn't read back from file",
					erri)
				return
			}
			if string(content) != string(tt.args.p) {
				t.Errorf("IOnodeFile.Write() content = %v, want %v",
					string(content), string(tt.args.p))
				return
			}
		})
	}
}

func TestIOnodeFile_Close(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime2", []byte("123"), 0644)

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i2 = ios.NewIOnode("uptime2", "/proc/uptime2", 0644)

	// Open sample file.
	i1.Open()

	// Test definition.
	tests := []struct {
		name    string
		i       domain.IOnode
		wantErr bool
	}{
		// Close a regular file.
		{"1", i1, false},

		// Close an un-opened file. Error expected.
		{"2", i2, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.i.Close(); (err != nil) != tt.wantErr {
				t.Errorf("IOnodeFile.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIOnodeFile_ReadAt(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime3", []byte("123456789"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime4", []byte("123"), 0644)

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i3 = ios.NewIOnode("uptime3", "/proc/uptime3", 0644)
	var i4 = ios.NewIOnode("uptime4", "/proc/uptime4", 0644)

	var i1Buff = make([]byte, 3)
	var i3Buff = make([]byte, 9)
	var i4Buff = make([]byte, 3)

	// Open sample files.
	_ = i1.Open()
	_ = i3.Open()

	// Test definition.
	type args struct {
		p   []byte
		off int64
	}
	tests := []struct {
		name    string
		i       domain.IOnode
		args    args
		wantN   int
		wantErr bool
	}{
		// Read at offset 0.
		{"1", i1, args{i1Buff, 0}, 3, false},

		// Read at EOF. Error expected.
		{"2", i1, args{i1Buff, 3}, 0, true},

		// Read beyond EOF. Error expected (not really that different from
		// previous one).
		{"3", i3, args{i3Buff, 10}, 0, true},

		// Read on un-opened file. Error expected.
		{"4", i4, args{i4Buff, 0}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Printf("rodny received %v", string(tt.args.p))
			gotN, err := tt.i.ReadAt(tt.args.p, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("IOnodeFile.ReadAt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("IOnodeFile.ReadAt() = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}

func TestIOnodeFile_ReadDirAll(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	AppFs.MkdirAll("/proc/sys", 0755)
	afero.WriteFile(AppFs, "/proc/sys/fs", []byte("456"), 0644)
	afero.WriteFile(AppFs, "/proc/sys/kernel", []byte("123"), 0644)
	afero.WriteFile(AppFs, "/proc/sys/net", []byte("789"), 0644)
	afero.WriteFile(AppFs, "/proc/sys/user", []byte("131415"), 0644)
	afero.WriteFile(AppFs, "/proc/sys/vm", []byte("101112"), 0644)

	var expected1 = []domain.FileInfo{
		domain.FileInfo{Fname: "fs", Fmode: 0644},
		domain.FileInfo{Fname: "kernel", Fmode: 0644},
		domain.FileInfo{Fname: "net", Fmode: 0644},
		domain.FileInfo{Fname: "user", Fmode: 0644},
		domain.FileInfo{Fname: "vm", Fmode: 0644},
	}
	var expected2 = []domain.FileInfo{}

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("sys", "/proc/sys", 0755|os.ModeDir)
	var i2 = ios.NewIOnode("sys1", "/proc/sys1", 0755|os.ModeDir)

	// Test definition.
	tests := []struct {
		name    string
		i       domain.IOnode
		want    []domain.FileInfo
		wantErr bool
	}{
		// ReadDir() from a regular directory.
		{"1", i1, expected1, false},

		// ReadDir() from a non-existing directory -- no matching afero-fs entry.
		// Error expected.
		{"2", i2, expected2, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.i.ReadDirAll()
			if (err != nil) != tt.wantErr {
				t.Errorf("IOnodeFile.ReadDirAll() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := 0; i < len(got); i++ {
				if got[i].Name() != tt.want[i].Name() || got[i].Mode() != tt.want[i].Mode() {
					t.Errorf("received Name() = %v, Mode() = %v, want Name() = %v, Mode = %v",
						got[i].Name(), got[i].Mode(), tt.want[i].Name(), tt.want[i].Mode())
				}
			}
		})
	}
}

func TestIOnodeFile_ReadLine(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime2", []byte("123\n456\n789"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime3", []byte(""), 0644)

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i2 = ios.NewIOnode("uptime2", "/proc/uptime2", 0644)
	var i3 = ios.NewIOnode("uptime3", "/proc/uptime3", 0644)
	var i4 = ios.NewIOnode("uptime4", "/proc/uptime4", 0644)

	// Test definition.
	tests := []struct {
		name string
		i    domain.IOnode
		want string
	}{
		// Readline from a regular file.
		{"1", i1, "123"},

		// Readline very first line from multi-line file.
		{"2", i2, "123"},

		// Readline from file with empty-line. Empty string should be returned.
		{"3", i3, ""},

		// Readline from a non-existing file -- no matching entry in afero-fs.
		// Empty string is expected.
		{"4", i4, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.i.ReadLine(); got != tt.want {
				t.Errorf("IOnodeFile.ReadLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIOnodeFile_Stat(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	AppFs.MkdirAll("/proc/sys", 0755)
	afero.WriteFile(AppFs, "/proc/uptime", []byte("123"), 0644)

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("sys", "/proc/sys", 0755|os.ModeDir)
	var i2 = ios.NewIOnode("uptime", "/proc/uptime", 0644)

	var expected1 = domain.FileInfo{Fname: "sys", Fmode: 0755 | os.ModeDir}
	var expected2 = domain.FileInfo{Fname: "uptime", Fmode: 0644}

	// Test definition.
	tests := []struct {
		name    string
		i       domain.IOnode
		want    os.FileInfo
		wantErr bool
	}{
		// Stat() directory and verify that returned FileInfo match expectations.
		{"1", i1, expected1, false},

		// Stat() file and verify that returned FileInfo match expectations.
		{"2", i2, expected2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.i.Stat()
			if (err != nil) != tt.wantErr {
				t.Errorf("IOnodeFile.Stat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify that received os.FileInfo meets our expectations.
			if got.Name() != tt.want.Name() || got.Mode() != tt.want.Mode() {
				t.Errorf("received Name() = %v, Mode() = %v, want Name() = %v, Mode = %v",
					got.Name(), got.Mode(), tt.want.Name(), tt.want.Mode())
			}
		})
	}
}

func TestIOnodeFile_SeekReset(t *testing.T) {

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/uptime1", []byte("123456"), 0644)
	afero.WriteFile(AppFs, "/proc/uptime2", []byte("123456"), 0644)

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i2 = ios.NewIOnode("uptime2", "/proc/uptime2", 0644)

	// Let's open the file and read its entire content to place its offset at
	// EOF. This way we can test the seekReset() instruction further below.
	err := i1.Open()
	if err != nil {
		log.Printf("received error: %v", err)
	}
	buf := make([]byte, 3)
	_, err = i1.Read(buf)
	if err != nil {
		log.Printf("seek read failed with error: %v", err)
	}

	// Test definition.
	tests := []struct {
		name    string
		i       domain.IOnode
		want    int64
		wantErr bool
	}{
		// SeekReset() on file with offset preset at EOF.
		{"1", i1, 0, false},

		// SeekReset() on file that hasn't been opened. Error expected.
		{"2", i2, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.i.SeekReset()
			if (err != nil) != tt.wantErr {
				t.Errorf("IOnodeFile.SeekReset() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IOnodeFile.SeekReset() = %v, want %v", got, tt.want)
			}

			// Return at this point if an error is expected. Notice that
			// subsequent steps attempt to read from files again, so better
			// return here in these cases.
			if tt.wantErr {
				return
			}

			// Let's also ensure that the content of the original file and the
			// result of reading the file (taking into account the new offset),
			// is exactly the same, which would imply that seekReset() is doing
			// what expected.
			fileContent, erri := afero.ReadFile(AppFs, tt.i.Path())
			if erri != nil {
				t.Errorf("IOnodeFile.SeekReset() error = %v, couldn't read back from file",
					erri)
				return
			}

			// This second read() makes use of the existing 'offset' value, so
			// this one truly reflects what other 'read()' users would see after
			// executign seekReset().
			buf := make([]byte, len(string(fileContent)))
			_, erri = tt.i.Read(buf)
			if erri != nil {
				t.Errorf("IOnodeFile.SeekReset() content error: %v", erri)
				return
			}

			if string(fileContent) != string(buf) {
				t.Errorf("IOnodeFile.SeekReset() content = %v, want %v",
					string(fileContent), string(buf))
				return
			}
		})
	}
}

// Inode-extraction operation is not supported by afero-fs. Will leave this
// unit-testcase here for completeness' sake, as we should activate it once
// this functionality is implemented.
func TestIOnodeFile_PidNsInode(t *testing.T) {

	// Skipping this one for now.
	t.Skip("Skipping IOnodeFile.PidNsInode() for now")

	// Initialize memory-based mock FS.
	AppFs = afero.NewMemMapFs()

	// Create proc entries in mem-based FS.
	afero.WriteFile(AppFs, "/proc/123456/ns/pid", []byte("testing"), 0644)

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("", "123456", 0644)

	// Test definition.
	tests := []struct {
		name    string
		i       domain.IOnode
		want    domain.Inode
		wantErr bool
	}{
		{"1", i1, 12345658, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.i.PidNsInode()
			if (err != nil) != tt.wantErr {
				t.Errorf("IOnodeFile.PidNsInode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IOnodeFile.PidNsInode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIOnodeFile_Name(t *testing.T) {

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)

	// Test definition.
	tests := []struct {
		name string
		i    domain.IOnode
		want string
	}{
		// Lame UT to invoke Path() getter.
		{"1", i1, "uptime1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.i.Name(); got != tt.want {
				t.Errorf("IOnodeFile.Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIOnodeFile_Path(t *testing.T) {

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)

	// Test definition.
	tests := []struct {
		name string
		i    domain.IOnode
		want string
	}{
		// Lame UT to invoke Path() getter.
		{"1", i1, "/proc/uptime1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.i.Path(); got != tt.want {
				t.Errorf("IOnodeFile.Path() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIOnodeFile_OpenFlags(t *testing.T) {

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i2 = ios.NewIOnode("uptime2", "/proc/uptime2", 0644)
	i1.SetOpenFlags(syscall.O_WRONLY)
	i2.SetOpenFlags(syscall.O_RDWR)

	// Test definition.
	tests := []struct {
		name string
		i    domain.IOnode
		want int
	}{
		// Verify Openflags are properly extracted.
		{"1", i1, syscall.O_WRONLY},

		// Verify Openflags are properly extracted.
		{"2", i2, syscall.O_RDWR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.i.OpenFlags(); got != tt.want {
				t.Errorf("IOnodeFile.OpenFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIOnodeFile_SetOpenFlags(t *testing.T) {

	var ios = NewIOService(IOFileService)
	var i1 = ios.NewIOnode("uptime1", "/proc/uptime1", 0644)
	var i2 = ios.NewIOnode("uptime2", "/proc/uptime2", 0644)
	i1.SetOpenFlags(syscall.O_RDONLY)
	i2.SetOpenFlags(syscall.O_RDWR)

	// Test definition.
	type args struct {
		flags int
	}
	tests := []struct {
		name string
		i    domain.IOnode
		args args
	}{
		// Verify Openflags are properly set.
		{"1", i1, args{syscall.O_RDONLY}},

		// Verify Openflags are properly set.
		{"2", i2, args{syscall.O_RDWR}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.i.SetOpenFlags(tt.args.flags)
		})
	}
}
