package main

import (
	"context"
	"fmt"
	"os"

	"dagger.io/dagger"
)

func main() {
	ctx := context.Background()
	c, err := dagger.Connect(ctx, dagger.WithLogOutput(os.Stderr))
	if err != nil {
		panic(err)
	}

	src := c.Host().Directory(".")

	goVersion := "1.20.2"

	build := c.Container().
		From(fmt.Sprintf("golang:%s", goVersion)).
		WithMountedCache("/root/.cache/go-build", c.CacheVolume("gocache")).
		WithMountedCache("/go/pkg/mod", c.CacheVolume("gomodcache")).
		WithMountedDirectory("/app", src).
		WithWorkdir("/app").
		WithExec([]string{"go", "build", "."}).
		File("ldapweb")

	out, err := c.Container().
		From("gcr.io/distroless/static-debian11").
		WithFile("/ldapweb", build).
		WithEntrypoint([]string{"/ldapweb"}).
		WithDefaultArgs(dagger.ContainerWithDefaultArgsOpts{
			Args: []string{""},
		}).
		Publish(ctx, "dolanor/ldapweb:latest")
	if err != nil {
		panic(err)
	}
	fmt.Println(out)
}

// for future use when Go SDK get With()
func goImage(client *dagger.Client, version string) func(ctr *dagger.Container) *dagger.Container {
	return func(ctr *dagger.Container) *dagger.Container {
		return ctr.From(fmt.Sprintf("golang:%s", version)).
			WithMountedCache("/root/.cache/go-build", client.CacheVolume("gocache")).
			WithMountedCache("/go/pkg/mod", client.CacheVolume("gomodcache"))
	}

}
