# Laravel CloudWatch Tail

Tail Laravel log files and ship them to AWS CloudWatch Logs.

## Installation

```bash
composer require wndr/laravel-cloudwatch-tail
```

## Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag=cloudwatch-tail-config
```

### Environment Variables

Configure the following environment variables:

```env
CLOUDWATCH_LOG_GROUP_NAME=your-log-group-name
CLOUDWATCH_LOG_REGION=eu-west-1
CLOUDWATCH_LOG_KEY=your-aws-key
CLOUDWATCH_LOG_SECRET=your-aws-secret
```

If `CLOUDWATCH_LOG_KEY` and `CLOUDWATCH_LOG_SECRET` are not set, the AWS SDK will use the default credential provider chain (IAM roles, environment variables, etc.).

## Usage

Run the command to start shipping logs:

```bash
php artisan cloudwatch:ship-logs
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--dir` | `storage/logs` | Directory to watch for log files |
| `--pattern` | `*.log` | File pattern to match |
| `--group` | Config value | CloudWatch Log Group name |
| `--cursor` | `cloudwatch-cursors.json` | Cursor file (only used when cleanup is disabled) |
| `--flush-seconds` | `60` | Flush interval in seconds |
| `--max-bytes` | `900000` | Max batch bytes per stream before flush |
| `--refresh-seconds` | `120` | How often to rescan directory for new files |
| `--sleep-ms` | `200` | Loop sleep when idle (milliseconds) |
| `--cleanup-after-ship` | `true` | Truncate shipped files and delete old rotated logs |

## License

MIT
