<?php

use AlonePhp\Safe\SafeHelper;


/**
 * 加密成string
 * @param mixed $data
 * @param array $mode
 * @return string
 */
function alone_safe_url_en(mixed $data, array $mode = ['aes', 'des', 'des3']): string {
    return SafeHelper::urlEn($data, $mode);
}

/**
 * string解密
 * @param string $data
 * @return mixed
 */
function alone_safe_url_de(string $data): mixed {
    return SafeHelper::urlDe($data);
}


/**
 * 加密成array
 * @param mixed $data
 * @param array $mode
 * @return array
 */
function alone_safe_mov_en(mixed $data, array $mode = ['aes', 'des', 'des3']): array {
    return SafeHelper::movEn($data, $mode);
}

/**
 * array解密
 * @param array $data
 * @return mixed
 */
function alone_safe_mov_de(array $data): mixed {
    return SafeHelper::movDeArr($data);
}