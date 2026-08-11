# Upload module

ApiCore supports ordinary MIME multipart requests and resumable TUS 1.0 uploads. Both use the global upload root and disk-space policy.

## Paths and limits

| Setting | Default |
| --- | --- |
| `uploadPath` | `./uploads` |
| MIME staging directory | `<uploadPath>/mime` |
| TUS file directory | `<uploadPath>/tus` |
| `uploadMax` | 30 MiB |
| TUS chunk limit | 5 MiB |
| Orphan expiry | 24 hours |
| Cleanup mode | `lazy` |

Set `uploadMinDiskFreeMB` or `uploadMinDiskFreePercent` to reject file-backed uploads before they consume the configured free-space reserve.

## MIME multipart

Set `multipartEnabled: true` to parse multipart bodies for `ApiModule` routes. Parsed fields are available on `req.body`; uploaded files are exposed through the request wrapper and staged under the MIME directory.

## TUS

Mount TUS explicitly and choose its authentication policy:

```ts
import { ApiServer, TusUploadModule } from '@technomoron/apicore-server';

const server = new ApiServer({
	uploadPath: './uploads',
	uploadMax: 500 * 1024 * 1024
});

server.api(
	new TusUploadModule({
		auth: { type: 'strict', req: 'any' },
		basePath: '/api/v1/upload',
		validateUpload: ({ length, metadata }) => {
			if (length > 500 * 1024 * 1024) {
				throw new Error('Video is too large');
			}
			if (metadata.filetype && !metadata.filetype.startsWith('video/')) {
				throw new Error('Only video uploads are accepted');
			}
		},
		onUploadComplete: async (upload) => {
			console.log(upload.filepath);
		}
	})
);
```

The default store is file-backed. `MemoryTusUploadStore` is bounded and intended for tests or small temporary uploads. Client-supplied MIME metadata is not proof of file type; inspect completed file content before publishing or processing it.

TUS exposes `OPTIONS` and `POST` on the collection URL and `HEAD`, `PATCH`, and `DELETE` on the upload URL. `OPTIONS` is public protocol discovery. Other methods use the module’s explicit auth setting. Owned uploads cannot be accessed anonymously.

With `auth: { type: 'none' }`, the upload URL is a bearer capability: anyone who learns it can inspect, continue, or delete that incomplete upload. Use anonymous TUS only when that is the intended public API. The file store limits each upload and checks free disk space, but it does not limit the number of open upload records; apply request rate limits to public upload creation.

## Cleanup

Incomplete TUS uploads and staged MIME files expire. `lazy` cleanup runs opportunistically, `interval` uses a lightweight internal timer, and `off` disables automatic cleanup.

`POST <apiBasePath>/v1/uploads/purge` triggers cleanup immediately. It requires strict authentication with the `admin` authorization class. Completed TUS uploads are preserved.
