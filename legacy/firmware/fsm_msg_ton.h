/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2021 OneKey Team <core@onekey.so>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#undef COIN_TYPE
#define COIN_TYPE 607

void fsm_msgTonGetAddress(const TonGetAddress *msg) {
  // 检查系统是否已初始化
  CHECK_INITIALIZED;

  // 检查路径参数是否合法
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, ED25519_NAME, true),
              "Invalid path");

  // 检查用户是否已通过 PIN 验证
  CHECK_PIN;

  // 初始化响应消息
  RESP_INIT(TonAddress);

  // 派生节点
  HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  hdnode_fill_public_key(node);
  // 生成地址 - Working on it ##############################
  ton_get_address_from_public_key(node->public_key, resp->address);

  // 显示地址信息
  if (msg->has_show_display && msg->show_display) {
    char desc[16] = {0};
    strcat(desc, "Ton");
    strcat(desc, _("Address:"));
    if (!fsm_layoutAddress(resp->address, NULL, desc, false, 0, msg->address_n,
                           msg->address_n_count, false, NULL, 0, 0, NULL)) {
      return;
    }
  }

  // 发送响应消息
  msg_write(MessageType_MessageType_TonAddress, resp);

  // 返回主界面
  layoutHome();
}

void fsm_msgTonSignMessage(const TonSignMessage *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                                                      COIN_TYPE, SECP256K1_NAME, true),
                          "Invalid path");
  CHECK_PIN
  RESP_INIT(TonSignedMessage);
  const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                                                                  msg->address_n_count, NULL);
  if (!node) return;

  char signer_str[36];
  char address[36];

  ton_get_address_from_public_key(node->public_key, resp->address);

  ton_create_signed_message()
  
  ton_eth_2_ton_address(eth_address, signer_str, sizeof(signer_str));
  if (!fsm_layoutSignMessage("Ton", signer_str, msg->comment,
                                                        sizeof(msg->comment))) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
  }
  resp->address.size = strlen(signer_str);
  memcpy(resp->address.bytes, signer_str, resp->address.size);
  ton_message_sign(msg, node, resp);
  layoutHome();
}