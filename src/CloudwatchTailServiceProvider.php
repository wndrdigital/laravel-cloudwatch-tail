<?php

namespace Wndr\CloudwatchTail;

use Illuminate\Support\ServiceProvider;
use Wndr\CloudwatchTail\Commands\ShipLogsToCloudWatch;

class CloudwatchTailServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/cloudwatch-tail.php',
            'cloudwatch-tail'
        );
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/cloudwatch-tail.php' => config_path('cloudwatch-tail.php'),
            ], 'cloudwatch-tail-config');

            $this->commands([
                ShipLogsToCloudWatch::class,
            ]);
        }
    }
}
