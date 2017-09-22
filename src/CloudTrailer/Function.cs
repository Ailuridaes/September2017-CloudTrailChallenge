using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.Lambda.Core;
using Amazon.Lambda.SNSEvents;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using CloudTrailer.Models;
using Newtonsoft.Json;


// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace CloudTrailer
{
    public class Function
    {
        private static readonly byte[] GZipHeaderBytes = {0x1f, 0x8b};
//        private static readonly byte[] GZipHeaderBytes = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 4, 0};

        private IAmazonS3 S3Client { get; }
        private IAmazonSimpleNotificationService SnsClient { get; }
        private IAmazonIdentityManagementService IamClient { get; }
        private static string AlertTopicArn => Environment.GetEnvironmentVariable("AlertTopicArn");
        private readonly string CreateUserTopicArn = "arn:aws:sns:us-west-2:311339799303:cloudtrail-create-user-events";

        /// <summary>
        /// Default constructor. This constructor is used by Lambda to construct the instance. When invoked in a Lambda environment
        /// the AWS credentials will come from the IAM role associated with the function and the AWS region will be set to the
        /// region the Lambda function is executed in.
        /// </summary>
        public Function()
        {
            S3Client = new AmazonS3Client();
            SnsClient = new AmazonSimpleNotificationServiceClient();
            IamClient = new AmazonIdentityManagementServiceClient();
        }

        public async Task FunctionHandler(SNSEvent evnt, ILambdaContext context)
        {
            // ### Level 1 - Create New Trail and Configure Lambda
            // context.Logger.LogLine(JsonConvert.SerializeObject(evnt));

            // ### Level 2 - Retrieve Logs from S3
            CloudTrailMessage message = JsonConvert.DeserializeObject<CloudTrailMessage>(evnt.Records[0].Sns.Message);
            context.Logger.LogLine($"Bucket: {message.S3Bucket} Object key: {message.S3ObjectKey[0]}");
            GetObjectRequest request = new GetObjectRequest 
            {
                BucketName = message.S3Bucket,
                Key = message.S3ObjectKey[0]
            };

            byte[] responseByteArray;
            using (GetObjectResponse response = await S3Client.GetObjectAsync(request))
            {
                using (Stream responseStream = response.ResponseStream)
                using(var memoryStream = new MemoryStream())
                {
                    responseStream.CopyTo(memoryStream);
                    responseByteArray = memoryStream.ToArray();
                }
            }
            var records = await ExtractCloudTrailRecordsAsync(context.Logger, responseByteArray);

            // ### Level 3 - Filter for specific events and send alerts]
            foreach (var r in records.Records)
            {
                if(r.EventName == "CreateUser") {
                    context.Logger.LogLine($"Super cool event '{r.EventName}'");
                    var publishRequest = new PublishRequest
                    {
                        Subject = "Super cool event ALERT",
                        Message = $"You have a super cool event \n {r.EventName} for user {r.RequestParameters["userName"]}",
                        TopicArn = CreateUserTopicArn
                    };
                    await SnsClient.PublishAsync(publishRequest);
                }
            }

            // ### Boss level - Take mitigating action
        }


        private async Task<CloudTrailRecords> ExtractCloudTrailRecordsAsync(ILambdaLogger logger, byte[] input)
        {
            var appearsGzipped = ResponseAppearsGzipped(input);
            logger.LogLine($"Input appears to be gzipped: {appearsGzipped}");
            if (appearsGzipped)
            {
                using (var contents = new MemoryStream())
                using (var gz = new GZipStream(new MemoryStream(input), CompressionMode.Decompress))
                {
                    await gz.CopyToAsync(contents);
                    input = contents.ToArray();
                }
            }

            var serializedRecords = Encoding.UTF8.GetString(input);
            logger.Log(serializedRecords);
            return JsonConvert.DeserializeObject<CloudTrailRecords>(serializedRecords);

            bool ResponseAppearsGzipped(byte[] bytes)
            {
                var header = new byte[GZipHeaderBytes.Length];
                Array.Copy(bytes, header, header.Length);
                return header.SequenceEqual(GZipHeaderBytes);
            }
        }
    }
}