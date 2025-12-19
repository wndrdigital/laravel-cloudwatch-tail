<?php

return [
    /*
    |--------------------------------------------------------------------------
    | CloudWatch Log Group Name
    |--------------------------------------------------------------------------
    |
    | The name of the CloudWatch Log Group where logs will be shipped.
    |
    */
    'log_group_name' => env('CLOUDWATCH_LOG_GROUP_NAME'),

    /*
    |--------------------------------------------------------------------------
    | AWS Region
    |--------------------------------------------------------------------------
    |
    | The AWS region where your CloudWatch Logs are located.
    |
    */
    'region' => env('CLOUDWATCH_LOG_REGION', 'eu-west-1'),

    /*
    |--------------------------------------------------------------------------
    | AWS SDK Version
    |--------------------------------------------------------------------------
    |
    | The version of the CloudWatch Logs API to use.
    |
    */
    'version' => env('CLOUDWATCH_LOG_VERSION', 'latest'),

    /*
    |--------------------------------------------------------------------------
    | AWS Credentials
    |--------------------------------------------------------------------------
    |
    | The AWS credentials for accessing CloudWatch Logs.
    | If not provided, the SDK will use the default credential provider chain.
    |
    */
    'credentials' => [
        'key' => env('CLOUDWATCH_LOG_KEY'),
        'secret' => env('CLOUDWATCH_LOG_SECRET'),
    ],
];
