
package domain

type IpcServiceIface interface {
	Setup(
		css ContainerStateServiceIface,
		prs ProcessServiceIface,
		ios IOServiceIface)

	Init() error
}
