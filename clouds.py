import dropbox

class DropboxCloud:

    token = 'BIHEAThi-nQAAAAAAAAAYSqX7tpWpHvnJ9sLl-rKKTesKkZXm7iwwLbIFHGalf99'
    client = dropbox.client.DropboxClient(token)
    dbx = dropbox.Dropbox(token)

    @staticmethod
    def clear():
        folder_metadata = DropboxCloud.client.metadata('/')
        for f in folder_metadata['contents']:
            print('Deleting ', f['path'])
            DropboxCloud.client.file_delete(f['path'])

    @staticmethod
    def put(k, v):
        # put file with name k and content v
        DropboxCloud.client.put_file(k, v)


    @staticmethod
    def drop_single(self, item):
        self.dbx.files_upload_session_start(item[1], False)

    @staticmethod
    def put_batch(self, files):
        #upload_session_start_result = dbx.files_upload_session_start(files[0][0]))

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        #executor.map(self.drop_single, range(5,0,-1))
        futures = [executor.submit(self.drop_single, item) for item in files]
        concurrent.futures.wait(futures)

        return
        for i, (file_name, file_content) in enumerate(files):
            if i+1 < len(files):
                self.dbx.files_upload_session_start(file_content, False)
                print('Upload batch %s' % file_name)
            else:
                self.dbx.files_upload_session_start(file_content, True)
                print('Upload batch %s CLOSE' % file_name)

        #self.dbx.files_upload_session_finish_batch()

    @staticmethod
    def get(k):
        try :
            # get file with name k
            f, metadata = DropboxCloud.client.get_file_and_metadata('/' + k)
            return f.read()
        except dropbox.rest.ErrorResponse:
            return None

    @staticmethod
    def put_overwrite(k, v):
        DropboxCloud.dbx.files_upload(str.encode(v), '/' + k,
            mode=dropbox.files.WriteMode.overwrite)

    @staticmethod
    def put_overwrite_b(k, v):
        DropboxCloud.dbx.files_upload(v, '/' + k,
            mode=dropbox.files.WriteMode.overwrite)
