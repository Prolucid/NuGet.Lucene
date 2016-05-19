using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using AspNet.WebApi.HtmlMicrodataFormatter;
using Lucene.Net.Linq;
using NuGet.Lucene.Util;
using NuGet.Lucene.Web.Models;
using NuGet.Lucene.Web.Symbols;
using NuGet.Lucene.Web.Util;
using System.IO;

namespace NuGet.Lucene.Web.Controllers
{
	internal static class HttpHeaderExtensions
	{
		public static void CopyTo(this HttpContentHeaders fromHeaders, HttpContentHeaders toHeaders)
		{
			foreach (KeyValuePair<string, IEnumerable<string>> header in fromHeaders)
			{
				toHeaders.TryAddWithoutValidation(header.Key, header.Value);
			}
		}
	}

	internal abstract class DelegatingStream : Stream
	{
		private Stream _innerStream;

		protected DelegatingStream(Stream innerStream)
		{
			if (innerStream == null)
			{
				throw new ArgumentNullException();
			}
			_innerStream = innerStream;
		}

		protected Stream InnerStream
		{
			get { return _innerStream; }
		}

		public override bool CanRead
		{
			get { return _innerStream.CanRead; }
		}

		public override bool CanSeek
		{
			get { return _innerStream.CanSeek; }
		}

		public override bool CanWrite
		{
			get { return _innerStream.CanWrite; }
		}

		public override long Length
		{
			get { return _innerStream.Length; }
		}

		public override long Position
		{
			get { return _innerStream.Position; }
			set { _innerStream.Position = value; }
		}

		public override int ReadTimeout
		{
			get { return _innerStream.ReadTimeout; }
			set { _innerStream.ReadTimeout = value; }
		}

		public override bool CanTimeout
		{
			get { return _innerStream.CanTimeout; }
		}

		public override int WriteTimeout
		{
			get { return _innerStream.WriteTimeout; }
			set { _innerStream.WriteTimeout = value; }
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				_innerStream.Dispose();
			}
			base.Dispose(disposing);
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			return _innerStream.Seek(offset, origin);
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			return _innerStream.Read(buffer, offset, count);
		}

		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			return _innerStream.ReadAsync(buffer, offset, count, cancellationToken);
		}

		#if !NETFX_CORE // BeginX and EndX not supported on Streams in portable libraries
		public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
		return _innerStream.BeginRead(buffer, offset, count, callback, state);
		}

		public override int EndRead(IAsyncResult asyncResult)
		{
		return _innerStream.EndRead(asyncResult);
		}
		#endif

		public override int ReadByte()
		{
			return _innerStream.ReadByte();
		}

		public override void Flush()
		{
			_innerStream.Flush();
		}

		public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
		{
			return _innerStream.CopyToAsync(destination, bufferSize, cancellationToken);
		}

		public override Task FlushAsync(CancellationToken cancellationToken)
		{
			return _innerStream.FlushAsync(cancellationToken);
		}

		public override void SetLength(long value)
		{
			_innerStream.SetLength(value);
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			_innerStream.Write(buffer, offset, count);
		}

		public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			return _innerStream.WriteAsync(buffer, offset, count, cancellationToken);
		}

		#if !NETFX_CORE // BeginX and EndX not supported on Streams in portable libraries
		public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
		return _innerStream.BeginWrite(buffer, offset, count, callback, state);
		}

		public override void EndWrite(IAsyncResult asyncResult)
		{
		_innerStream.EndWrite(asyncResult);
		}
		#endif

		public override void WriteByte(byte value)
		{
			_innerStream.WriteByte(value);
		}
	}

	internal class ByteRangeStream : DelegatingStream
	{
		// The offset stream position at which the range starts.
		private readonly long _lowerbounds;

		// The total number of bytes within the range. 
		private readonly long _totalCount;

		// The current number of bytes read into the range
		private long _currentCount;

		public ByteRangeStream(Stream innerStream, RangeItemHeaderValue range)
			: base(innerStream)
		{
			// Ranges are inclusive so 0-9 means the first 10 bytes
			long maxLength = innerStream.Length - 1;
			long upperbounds;
			if (range.To.HasValue)
			{
				if (range.From.HasValue)
				{
					// e.g bytes=0-499 (the first 500 bytes offsets 0-499)
					upperbounds = Math.Min(range.To.Value, maxLength);
					_lowerbounds = range.From.Value;
				}
				else
				{
					// e.g bytes=-500 (the final 500 bytes)
					upperbounds = maxLength;
					_lowerbounds = Math.Max(innerStream.Length - range.To.Value, 0);
				}
			}
			else
			{
				if (range.From.HasValue)
				{
					// e.g bytes=500- (from byte offset 500 and up)
					upperbounds = maxLength;
					_lowerbounds = range.From.Value;
				}
				else
				{
					// e.g. bytes=- (invalid so will never get here)
					upperbounds = maxLength;
					_lowerbounds = 0;
				}
			}

			_totalCount = upperbounds - _lowerbounds + 1;
			ContentRange = new ContentRangeHeaderValue(_lowerbounds, upperbounds, innerStream.Length);
		}

		public ContentRangeHeaderValue ContentRange { get; private set; }

		public override long Length
		{
			get { return _totalCount; }
		}

		public override bool CanWrite
		{
			get { return false; }
		}

		public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
		{
			int effectiveCount = PrepareStreamForRangeRead(1);
			if (effectiveCount <= 0)
			{
				throw new IndexOutOfRangeException();
			}
			return base.CopyToAsync(destination, bufferSize, cancellationToken);
		}

		public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
			return base.BeginRead(buffer, offset, PrepareStreamForRangeRead(count), callback, state);
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			return base.Read(buffer, offset, PrepareStreamForRangeRead(count));
		}

		public override int ReadByte()
		{
			int effectiveCount = PrepareStreamForRangeRead(1);
			if (effectiveCount <= 0)
			{
				return -1;
			}
			return base.ReadByte();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}

		public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
			throw new NotSupportedException();
		}

		public override void EndWrite(IAsyncResult asyncResult)
		{
			throw new NotSupportedException();
		}

		public override void WriteByte(byte value)
		{
			throw new NotSupportedException();
		}

		/// <summary>
		/// Gets the 
		/// </summary>
		/// <param name="count">The count requested to be read by the caller.</param>
		/// <returns>The remaining bytes to read within the range defined for this stream.</returns>
		private int PrepareStreamForRangeRead(int count)
		{
			long effectiveCount = Math.Min(count, _totalCount - _currentCount);
			if (effectiveCount > 0)
			{
				// Check if we should update the stream position
				long position = InnerStream.Position;
				if (_lowerbounds + _currentCount != position)
				{
					InnerStream.Position = _lowerbounds + _currentCount;
				}

				// Update current number of bytes read
				_currentCount += effectiveCount;
			}

			// Effective count can never be bigger than int
			return (int)effectiveCount;
		}
	}
		/// <summary>
		/// <see cref="HttpContent"/> implementation which provides a byte range view over a stream used to generate HTTP
		/// 206 (Partial Content) byte range responses. The <see cref="ByteRangeStreamContent"/> supports one or more 
		/// byte ranges regardless of whether the ranges are consecutive or not. If there is only one range then a 
		/// single partial response body containing a Content-Range header is generated. If there are more than one
		/// ranges then a multipart/byteranges response is generated where each body part contains a range indicated
		/// by the associated Content-Range header field.
		/// </summary>
		public class ByteRangeStreamContent : HttpContent
		{
			private const string SupportedRangeUnit = "bytes";
			private const string ByteRangesContentSubtype = "byteranges";
			private const int DefaultBufferSize = 4096;
			private const int MinBufferSize = 1;

			private readonly Stream _content;
			private readonly long _start;
			private readonly HttpContent _byteRangeContent;
			private bool _disposed;

			/// <summary>
			/// <see cref="HttpContent"/> implementation which provides a byte range view over a stream used to generate HTTP
			/// 206 (Partial Content) byte range responses. If none of the requested ranges overlap with the current extend 
			/// of the selected resource represented by the <paramref name="content"/> parameter then an 
			/// <see cref="InvalidByteRangeException"/> is thrown indicating the valid Content-Range of the content. 
			/// </summary>
			/// <param name="content">The stream over which to generate a byte range view.</param>
			/// <param name="range">The range or ranges, typically obtained from the Range HTTP request header field.</param>
			/// <param name="mediaType">The media type of the content stream.</param>
			public ByteRangeStreamContent(Stream content, RangeHeaderValue range, string mediaType)
				: this(content, range, new MediaTypeHeaderValue(mediaType), DefaultBufferSize)
			{
			}

			/// <summary>
			/// <see cref="HttpContent"/> implementation which provides a byte range view over a stream used to generate HTTP
			/// 206 (Partial Content) byte range responses. If none of the requested ranges overlap with the current extend 
			/// of the selected resource represented by the <paramref name="content"/> parameter then an 
			/// <see cref="InvalidByteRangeException"/> is thrown indicating the valid Content-Range of the content. 
			/// </summary>
			/// <param name="content">The stream over which to generate a byte range view.</param>
			/// <param name="range">The range or ranges, typically obtained from the Range HTTP request header field.</param>
			/// <param name="mediaType">The media type of the content stream.</param>
			/// <param name="bufferSize">The buffer size used when copying the content stream.</param>
			public ByteRangeStreamContent(Stream content, RangeHeaderValue range, string mediaType, int bufferSize)
				: this(content, range, new MediaTypeHeaderValue(mediaType), bufferSize)
			{
			}

			/// <summary>
			/// <see cref="HttpContent"/> implementation which provides a byte range view over a stream used to generate HTTP
			/// 206 (Partial Content) byte range responses. If none of the requested ranges overlap with the current extend 
			/// of the selected resource represented by the <paramref name="content"/> parameter then an 
			/// <see cref="InvalidByteRangeException"/> is thrown indicating the valid Content-Range of the content. 
			/// </summary>
			/// <param name="content">The stream over which to generate a byte range view.</param>
			/// <param name="range">The range or ranges, typically obtained from the Range HTTP request header field.</param>
			/// <param name="mediaType">The media type of the content stream.</param>
			public ByteRangeStreamContent(Stream content, RangeHeaderValue range, MediaTypeHeaderValue mediaType)
				: this(content, range, mediaType, DefaultBufferSize)
			{
			}

			/// <summary>
			/// <see cref="HttpContent"/> implementation which provides a byte range view over a stream used to generate HTTP
			/// 206 (Partial Content) byte range responses. If none of the requested ranges overlap with the current extend 
			/// of the selected resource represented by the <paramref name="content"/> parameter then an 
			/// <see cref="InvalidByteRangeException"/> is thrown indicating the valid Content-Range of the content. 
			/// </summary>
			/// <param name="content">The stream over which to generate a byte range view.</param>
			/// <param name="range">The range or ranges, typically obtained from the Range HTTP request header field.</param>
			/// <param name="mediaType">The media type of the content stream.</param>
			/// <param name="bufferSize">The buffer size used when copying the content stream.</param>
			public ByteRangeStreamContent(Stream content, RangeHeaderValue range, MediaTypeHeaderValue mediaType, int bufferSize)
			{

				try
				{
					// If we have more than one range then we use a multipart/byteranges content type as wrapper.
					// Otherwise we use a non-multipart response.
					if (range.Ranges.Count > 1)
					{
						// Create Multipart content and copy headers to this content
						MultipartContent rangeContent = new MultipartContent(ByteRangesContentSubtype);
						_byteRangeContent = rangeContent;

						foreach (RangeItemHeaderValue rangeValue in range.Ranges)
						{
							try
							{
								ByteRangeStream rangeStream = new ByteRangeStream(content, rangeValue);
								HttpContent rangeBodyPart = new StreamContent(rangeStream, bufferSize);
								rangeBodyPart.Headers.ContentType = mediaType;
								rangeBodyPart.Headers.ContentRange = rangeStream.ContentRange;
								rangeContent.Add(rangeBodyPart);
							}
							catch (ArgumentOutOfRangeException)
							{
								// We ignore range errors until we check that we have at least one valid range
							}
						}

						// If no overlapping ranges were found then stop
						if (!rangeContent.Any())
						{
							ContentRangeHeaderValue actualContentRange = new ContentRangeHeaderValue(content.Length);
							string msg = "ByteRangeStreamNoneOverlap";
							throw new InvalidByteRangeException(actualContentRange, msg);
						}
					}
					else if (range.Ranges.Count == 1)
					{
						try
						{
							ByteRangeStream rangeStream = new ByteRangeStream(content, range.Ranges.First());
							_byteRangeContent = new StreamContent(rangeStream, bufferSize);
							_byteRangeContent.Headers.ContentType = mediaType;
							_byteRangeContent.Headers.ContentRange = rangeStream.ContentRange;
						}
						catch (ArgumentOutOfRangeException)
						{
							ContentRangeHeaderValue actualContentRange = new ContentRangeHeaderValue(content.Length);
							string msg = "ByteRangeStreamNoOverlap";
							throw new InvalidByteRangeException(actualContentRange, msg);
						}
					}
					else
					{
						throw new ArgumentException("range");
					}

					// Copy headers from byte range content so that we get the right content type etc.
					_byteRangeContent.Headers.CopyTo(Headers);

					_content = content;
					_start = content.Position;
				}
				catch
				{
					if (_byteRangeContent != null)
					{
						_byteRangeContent.Dispose();
					}
					throw;
				}
			}

			protected override Task SerializeToStreamAsync(Stream stream, TransportContext context)
			{
				// Reset stream to start position
				_content.Position = _start;

				// Copy result to output
				return _byteRangeContent.CopyToAsync(stream);
			}

			protected override bool TryComputeLength(out long length)
			{
				long? contentLength = _byteRangeContent.Headers.ContentLength;
				if (contentLength.HasValue)
				{
					length = contentLength.Value;
					return true;
				}

				length = -1;
				return false;
			}

			protected override void Dispose(bool disposing)
			{
				if (disposing)
				{
					if (!_disposed)
					{
						_byteRangeContent.Dispose();
						_content.Dispose();
						_disposed = true;
					}
				}
				base.Dispose(disposing);
			}
	}

    /// <summary>
    /// Provides methods to search, get metadata, download, upload and delete packages.
    /// </summary>
    public class PackagesController : ApiControllerBase
    {
        public ILucenePackageRepository LuceneRepository { get; set; }
        public IMirroringPackageRepository MirroringRepository { get; set; }
        public ISymbolSource SymbolSource { get; set; }
        public ITaskRunner TaskRunner { get; set; }

        /// <summary>
        /// Gets metadata about a package from the <c>nuspec</c> files and other
        /// metadata such as package size, date published, download counts, etc.
        /// </summary>
        public object GetPackageInfo(string id, string version="")
        {
            var packageSpec = new PackageSpec(id, version);
            var packages = LuceneRepository
                            .LucenePackages
                            .Where(p => p.Id == packageSpec.Id)
                            .OrderBy(p => p.Version)
                            .ToList();

            var package = packageSpec.Version != null
                              ? packages.Find(p => p.Version.SemanticVersion == packageSpec.Version)
                              : packages.LastOrDefault();

            if (package == null)
            {
                return Request.CreateErrorResponse(HttpStatusCode.NotFound, "Package not found.");
            }

            var versionHistory = packages.Select(pkg => new PackageVersionSummary(pkg, new Link(GetPackageInfoUrl(pkg), pkg.Version.ToString()))).ToList();

            versionHistory.Select(v => v.Link).SetRelationships(packages.IndexOf(package));

            var result = new PackageWithVersionHistory();

            package.ShallowClone(result);

            result.PackageDownloadLink = new Link(Url.Link(RouteNames.Packages.Download, new { id = result.Id, version = result.Version }), "attachment", "Download Package");
            result.VersionHistory = versionHistory.ToArray();
            result.SymbolsAvailable = SymbolSource.AreSymbolsPresentFor(package);

            return result;
        }

        private string GetPackageInfoUrl(LucenePackage pkg)
        {
            return Url.Link(RouteNames.Packages.Info, new { id = pkg.Id, version = pkg.Version });
        }

        /// <summary>
        /// Downloads the complete <c>.nupkg</c> content. The HTTP HEAD method
        /// is also supported for verifying package size, and modification date.
        /// The <c>ETag</c> response header will contain the md5 hash of the
        /// package content.
        /// </summary>
        [HttpGet, HttpHead]
        public HttpResponseMessage DownloadPackage(string id, string version="")
        {
            var packageSpec = new PackageSpec(id, version);
            var package = FindPackage(packageSpec);

            var result = EvaluateCacheHeaders(packageSpec, package);

            if (result != null)
            {
                return result;
            }

            var partial = Request.Headers.Range != null;
            result = Request.CreateResponse(partial ? HttpStatusCode.PartialContent : HttpStatusCode.OK);
            if (Request.Method == HttpMethod.Get)
            {
                if (partial)
                {
                    try
                    {
                        result.Content = new ByteRangeStreamContent(package.GetStream(), Request.Headers.Range, new MediaTypeWithQualityHeaderValue("application/zip"));
                    }
                    catch (InvalidByteRangeException e)
                    {
                        return Request.CreateErrorResponse(HttpStatusCode.BadRequest, e);
                    }
                }
                else
                {
                    result.Content = new StreamContent(package.GetStream());
                    TaskRunner.QueueBackgroundWorkItem(cancellationToken => LuceneRepository.IncrementDownloadCountAsync(package, cancellationToken));
                }
            }
            else
            {
                result.Content = new StringContent(string.Empty);
            }

            result.Headers.ETag = new EntityTagHeaderValue('"' + package.PackageHash + '"');
            result.Content.Headers.LastModified = package.LastUpdated;

            if (!partial)
            {
                result.Content.Headers.ContentType = new MediaTypeWithQualityHeaderValue("application/zip");
                result.Content.Headers.ContentDisposition = new ContentDispositionHeaderValue(DispositionTypeNames.Attachment)
                {
                    FileName = string.Format("{0}.{1}{2}", package.Id, package.Version, Constants.PackageExtension),
                    Size = package.PackageSize,
                    CreationDate = package.Created,
                    ModificationDate = package.LastUpdated,
                };
            }
            return result;
        }

        private HttpResponseMessage EvaluateCacheHeaders(PackageSpec packageSpec, LucenePackage package)
        {
            if (package == null)
            {
                return Request.CreateErrorResponse(HttpStatusCode.NotFound,
                                                     string.Format("Package {0} version {1} not found.", packageSpec.Id,
                                                                   packageSpec.Version));
            }

            var etagMatch = Request.Headers.IfMatch.Any(etag => !etag.IsWeak && etag.Tag == '"' + package.PackageHash + '"');
            var notModifiedSince = Request.Headers.IfModifiedSince.HasValue &&
                                   Request.Headers.IfModifiedSince >= package.LastUpdated;

            if (etagMatch || notModifiedSince)
            {
                return Request.CreateResponse(HttpStatusCode.NotModified);
            }

            return null;
        }

        /// <summary>
        /// Searches for packages that match <paramref name="query"/>, or if no query
        /// is provided, returns all packages in the repository.
        /// </summary>
        /// <param name="query">Search terms. May include special characters to support prefix,
        /// wildcard or phrase queries.
        /// </param>
        /// <param name="includePrerelease">Specify <c>true</c> to look for pre-release packages.</param>
        /// <param name="latestOnly">Specify <c>true</c> to only search most recent package version or <c>false</c> to search all versions</param>
        /// <param name="offset">Number of results to skip, for pagination.</param>
        /// <param name="count">Number of results to return, for pagination.</param>
        /// <param name="originFilter">Limit result to mirrored or local packages, or both.</param>
        /// <param name="sort">Specify field to sort results on. Score (relevance) is default.</param>
        /// <param name="order">Sort order (default:ascending or descending)</param>
        [HttpGet]
        public dynamic Search(
            string query = "",
            bool includePrerelease = false,
            bool latestOnly = true,
            int offset = 0,
            int count = 20,
            PackageOriginFilter originFilter = PackageOriginFilter.Any,
            SearchSortField sort = SearchSortField.Score,
            SearchSortDirection order = SearchSortDirection.Ascending)
        {
            var criteria = new SearchCriteria(query)
            {
                AllowPrereleaseVersions = includePrerelease,
                PackageOriginFilter = originFilter,
                SortField = sort,
                SortDirection = order
            };

            LuceneQueryStatistics stats = null;
            List<IPackage> hits;

            try
            {
                var queryable = LuceneRepository.Search(criteria).CaptureStatistics(s => stats = s);

                if (latestOnly)
                {
                    queryable = queryable.LatestOnly(includePrerelease);
                }

                hits = queryable.Skip(offset).Take(count).ToList();
            }
            catch (InvalidSearchCriteriaException ex)
            {
                var message = ex.InnerException != null ? ex.InnerException.Message : ex.Message;
                return Request.CreateErrorResponse(HttpStatusCode.BadRequest, message);
            }

            dynamic result = new ExpandoObject();

            // criteria
            result.Query = query;
            result.IncludePrerelease = includePrerelease;
            result.TotalHits = stats.TotalHits;
            result.OriginFilter = originFilter;
            result.Sort = sort;
            result.Order = order;

            // statistics
            result.Offset = stats.SkippedHits;
            result.Count = stats.RetrievedDocuments;
            result.ElapsedPreparationTime = stats.ElapsedPreparationTime;
            result.ElapsedSearchTime = stats.ElapsedSearchTime;
            result.ElapsedRetrievalTime = stats.ElapsedRetrievalTime;

            var chars = stats.Query.ToString().Normalize(NormalizationForm.FormD);
            result.ComputedQuery = new string(chars.Where(c => c < 0x7f && !char.IsControl(c)).ToArray());

            // hits
            result.Hits = hits;
            return result;
        }

        /// <summary>
        /// Gets a list of fields that can be searched using the advanced search function.
        /// </summary>
        [HttpGet]
        public IList<string> GetAvailableSearchFieldNames()
        {
            return LuceneRepository.GetAvailableSearchFieldNames().ToList();
        }

        /// <summary>
        /// Permanently delete a package from the repository.
        /// </summary>
        [Authorize(Roles=RoleNames.PackageManager)]
        public async Task<HttpResponseMessage> DeletePackage(string id, string version="")
        {
            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(version))
            {
                return Request.CreateErrorResponse(HttpStatusCode.BadRequest, "Must specify package id and version.");
            }

            var package = LuceneRepository.FindPackage(id, new SemanticVersion(version));

            if (package == null)
            {
                var message = string.Format("Package '{0}' version '{1}' not found.", id, version);
                return Request.CreateErrorResponse(HttpStatusCode.NotFound, message);
            }

            Audit("Delete package {0} version {1}", id, version);

            var task1 = LuceneRepository.RemovePackageAsync(package, CancellationToken.None);
            var task2 = SymbolSource.RemoveSymbolsAsync(package);

            await Task.WhenAll(task1, task2);

            return Request.CreateResponse(HttpStatusCode.OK);
        }

        /// <summary>
        /// Upload a package to the repository. If a package already exists
        /// with the same Id and Version, it will be replaced with the new package.
        /// </summary>
        [HttpPut]
        [HttpPost]
        [Authorize(Roles = RoleNames.PackageManager)]
        public async Task<HttpResponseMessage> PutPackage([FromBody]IPackage package)
        {
            if (package == null || string.IsNullOrWhiteSpace(package.Id) || package.Version == null)
            {
                return Request.CreateErrorResponse(HttpStatusCode.BadRequest, "Must provide package with valid id and version.");
            }

            if (package.HasSourceAndSymbols())
            {
                var response = Request.CreateResponse(HttpStatusCode.RedirectKeepVerb);
                response.Headers.Location = new Uri(Url.Link(RouteNames.Symbols.Upload, null), UriKind.RelativeOrAbsolute);
                return response;
            }

            try
            {
                Audit("Add package {0} version {1}", package.Id, package.Version);
                await LuceneRepository.AddPackageAsync(package, CancellationToken.None);
            }
            catch (PackageOverwriteDeniedException ex)
            {
                return Request.CreateErrorResponse(HttpStatusCode.Conflict, ex.Message);
            }

            var location = Url.Link(RouteNames.Packages.Info, new { id = package.Id, version = package.Version });
            var result = Request.CreateResponse(HttpStatusCode.Created);
            result.Headers.Location = new Uri(location);
            return result;
        }

        private LucenePackage FindPackage(PackageSpec packageSpec)
        {
            if (packageSpec.Version == null)
            {
                return FindNewestReleasePackage(packageSpec.Id);
            }

            var package = MirroringRepository.FindPackage(packageSpec.Id, packageSpec.Version);
            return package != null ? LuceneRepository.Convert(package) : null;
        }

        private LucenePackage FindNewestReleasePackage(string packageId)
        {
            return (LucenePackage) LuceneRepository
                    .FindPackagesById(packageId)
                    .Where(p => p.IsReleaseVersion())
                    .OrderByDescending(p => p.Version)
                    .FirstOrDefault();
        }
    }
}
