<?php

namespace AlonePack\Phpseclib3\Exception;

/**
 * Indicates an absent or malformed packet length header
 */
class InvalidPacketLengthException extends ConnectionClosedException
{
}