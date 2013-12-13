<?php
namespace Psecio\Versionscan\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputOption;

class ScanCommand extends Command
{
    protected function configure()
    {
        $this->setName('scan')
            ->setDescription('Report back vulnerabilities for the current PHP version')
            ->setDefinition(array(
                new InputOption('php-version', 'php-version', InputOption::VALUE_OPTIONAL, 'PHP version to check'),
            ))
            ->setHelp(
                'Execute the scan on the current PHP version'
            );
    }

    /**
     * Execute the "scan" command
     *
     * @param  InputInterface $input Input object
     * @param  OutputInterface $output Output object
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $scan = new \Psecio\Versionscan\Scan();
        $scan->execute();

        $output->writeLn('Running scan!');
    }
}

?>
