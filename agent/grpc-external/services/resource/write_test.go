package resource

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/hashicorp/consul/acl/resolver"
	"github.com/hashicorp/consul/internal/resource/demo"
	"github.com/hashicorp/consul/internal/storage"
	"github.com/hashicorp/consul/proto-public/pbresource"
	pbdemov2 "github.com/hashicorp/consul/proto/private/pbdemo/v2"
)

func TestWrite_InputValidation(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	testCases := map[string]func(*pbresource.WriteRequest){
		"no resource": func(req *pbresource.WriteRequest) { req.Resource = nil },
		"no id":       func(req *pbresource.WriteRequest) { req.Resource.Id = nil },
		"no type":     func(req *pbresource.WriteRequest) { req.Resource.Id.Type = nil },
		"no tenancy":  func(req *pbresource.WriteRequest) { req.Resource.Id.Tenancy = nil },
		"no name":     func(req *pbresource.WriteRequest) { req.Resource.Id.Name = "" },
		"no data":     func(req *pbresource.WriteRequest) { req.Resource.Data = nil },
		"wrong data type": func(req *pbresource.WriteRequest) {
			var err error
			req.Resource.Data, err = anypb.New(&pbdemov2.Album{})
			require.NoError(t, err)
		},
		"fail validation hook": func(req *pbresource.WriteRequest) {
			artist := &pbdemov2.Artist{}
			require.NoError(t, req.Resource.Data.UnmarshalTo(artist))
			artist.Name = "" // name cannot be empty
			require.NoError(t, req.Resource.Data.MarshalFrom(artist))
		},
	}
	for desc, modFn := range testCases {
		t.Run(desc, func(t *testing.T) {
			res, err := demo.GenerateV2Artist()
			require.NoError(t, err)

			req := &pbresource.WriteRequest{Resource: res}
			modFn(req)

			_, err = client.Write(testContext(t), req)
			require.Error(t, err)
			require.Equal(t, codes.InvalidArgument.String(), status.Code(err).String())
		})
	}
}

func TestWrite_TypeNotFound(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	_, err = client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument.String(), status.Code(err).String())
	require.Contains(t, err.Error(), "resource type demo.v2.artist not registered")
}

func TestWrite_ACLs(t *testing.T) {
	type testCase struct {
		authz       resolver.Result
		assertErrFn func(error)
	}
	testcases := map[string]testCase{
		"write denied": {
			authz: AuthorizerFrom(t, demo.ArtistV1WritePolicy),
			assertErrFn: func(err error) {
				require.Error(t, err)
				require.Equal(t, codes.PermissionDenied.String(), status.Code(err).String())
			},
		},
		"write allowed": {
			authz: AuthorizerFrom(t, demo.ArtistV2WritePolicy),
			assertErrFn: func(err error) {
				require.NoError(t, err)
			},
		},
	}

	for desc, tc := range testcases {
		t.Run(desc, func(t *testing.T) {
			server := testServer(t)
			client := testClient(t, server)

			mockACLResolver := &MockACLResolver{}
			mockACLResolver.On("ResolveTokenAndDefaultMeta", mock.Anything, mock.Anything, mock.Anything).
				Return(tc.authz, nil)
			server.ACLResolver = mockACLResolver
			demo.Register(server.Registry)

			artist, err := demo.GenerateV2Artist()
			require.NoError(t, err)

			// exercise ACL
			_, err = client.Write(testContext(t), &pbresource.WriteRequest{Resource: artist})
			tc.assertErrFn(err)
		})
	}
}

func TestWrite_ResourceCreation_Success(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	rsp, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)
	require.NotEmpty(t, rsp.Resource.Version, "resource should have version")
	require.NotEmpty(t, rsp.Resource.Id.Uid, "resource id should have uid")
	require.NotEmpty(t, rsp.Resource.Generation, "resource should have generation")
}

func TestWrite_CASUpdate_Success(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	rsp1, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)

	rsp2, err := client.Write(testContext(t), &pbresource.WriteRequest{
		Resource: modifyArtist(t, rsp1.Resource),
	})
	require.NoError(t, err)

	require.Equal(t, rsp1.Resource.Id.Uid, rsp2.Resource.Id.Uid)
	require.NotEqual(t, rsp1.Resource.Version, rsp2.Resource.Version)
	require.NotEqual(t, rsp1.Resource.Generation, rsp2.Resource.Generation)
}

func TestWrite_ResourceCreation_StatusProvided(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	res.Status = map[string]*pbresource.Status{
		"consul.io/some-controller": {ObservedGeneration: ulid.Make().String()},
	}

	_, err = client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument.String(), status.Code(err).String())
	require.Contains(t, err.Error(), "WriteStatus endpoint")
}

func TestWrite_CASUpdate_Failure(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	rsp1, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)

	res = modifyArtist(t, rsp1.Resource)
	res.Version = "wrong-version"

	_, err = client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.Error(t, err)
	require.Equal(t, codes.Aborted.String(), status.Code(err).String())
	require.Contains(t, err.Error(), "CAS operation failed")
}

func TestWrite_Update_WrongUid(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	rsp1, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)

	res = modifyArtist(t, rsp1.Resource)
	res.Id.Uid = "wrong-uid"

	_, err = client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition.String(), status.Code(err).String())
	require.Contains(t, err.Error(), "uid doesn't match")
}

func TestWrite_Update_StatusModified(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	rsp1, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)

	statusRsp, err := client.WriteStatus(testContext(t), validWriteStatusRequest(t, rsp1.Resource))
	require.NoError(t, err)
	res = statusRsp.Resource

	// Passing the staus unmodified should be fine.
	rsp2, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)

	// Attempting to modify the status should return an error.
	res = rsp2.Resource
	res.Status["consul.io/other-controller"] = &pbresource.Status{ObservedGeneration: res.Generation}

	_, err = client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument.String(), status.Code(err).String())
	require.Contains(t, err.Error(), "WriteStatus endpoint")
}

func TestWrite_Update_NilStatus(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	rsp1, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)

	statusRsp, err := client.WriteStatus(testContext(t), validWriteStatusRequest(t, rsp1.Resource))
	require.NoError(t, err)

	// Passing a nil status should be fine (and carry over the old status).
	res = statusRsp.Resource
	res.Status = nil

	rsp2, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)
	require.NotEmpty(t, rsp2.Resource.Status)
}

func TestWrite_Update_NoUid(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	rsp1, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)

	res = modifyArtist(t, rsp1.Resource)
	res.Id.Uid = ""

	_, err = client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)
}

func TestWrite_NonCASUpdate_Success(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	rsp1, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)

	res = modifyArtist(t, rsp1.Resource)
	res.Version = ""

	rsp2, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)
	require.NotEmpty(t, rsp2.Resource.Version)
	require.NotEqual(t, rsp1.Resource.Version, rsp2.Resource.Version)
}

func TestWrite_NonCASUpdate_Retry(t *testing.T) {
	server := testServer(t)
	client := testClient(t, server)

	demo.Register(server.Registry)

	res, err := demo.GenerateV2Artist()
	require.NoError(t, err)

	rsp1, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
	require.NoError(t, err)

	// Simulate conflicting writes by blocking the RPC after it has read the
	// current version of the resource, but before it tries to make a write.
	backend := &blockOnceBackend{
		Backend: server.Backend,

		readCh:  make(chan struct{}),
		blockCh: make(chan struct{}),
	}
	server.Backend = backend

	errCh := make(chan error)
	go func() {
		res := modifyArtist(t, rsp1.Resource)
		res.Version = ""

		_, err := client.Write(testContext(t), &pbresource.WriteRequest{Resource: res})
		errCh <- err
	}()

	// Wait for the read, to ensure the Write in the goroutine above has read the
	// current version of the resource.
	<-backend.readCh

	// Update the resource.
	res = modifyArtist(t, rsp1.Resource)
	_, err = backend.WriteCAS(testContext(t), res)
	require.NoError(t, err)

	// Unblock the read.
	close(backend.blockCh)

	// Check that the write succeeded anyway because of a retry.
	require.NoError(t, <-errCh)
}

type blockOnceBackend struct {
	storage.Backend

	done    uint32
	readCh  chan struct{}
	blockCh chan struct{}
}

func (b *blockOnceBackend) Read(ctx context.Context, consistency storage.ReadConsistency, id *pbresource.ID) (*pbresource.Resource, error) {
	res, err := b.Backend.Read(ctx, consistency, id)

	// Block for exactly one call to Read. All subsequent calls (including those
	// concurrent to the blocked call) will return immediately.
	if atomic.CompareAndSwapUint32(&b.done, 0, 1) {
		close(b.readCh)
		<-b.blockCh
	}

	return res, err
}