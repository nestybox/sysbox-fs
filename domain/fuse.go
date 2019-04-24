package domain

type FuseService interface {
	Run() error
	MountPoint() string
	Unmount()
}
