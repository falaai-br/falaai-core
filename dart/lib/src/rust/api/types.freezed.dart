// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'types.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$ChatEvent {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ChatEvent);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'ChatEvent()';
}


}

/// @nodoc
class $ChatEventCopyWith<$Res>  {
$ChatEventCopyWith(ChatEvent _, $Res Function(ChatEvent) __);
}


/// Adds pattern-matching-related methods to [ChatEvent].
extension ChatEventPatterns on ChatEvent {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( ChatEvent_MessageReceived value)?  messageReceived,TResult Function( ChatEvent_MessageSent value)?  messageSent,TResult Function( ChatEvent_MessageFailed value)?  messageFailed,TResult Function( ChatEvent_ReceiptReceived value)?  receiptReceived,TResult Function( ChatEvent_Typing value)?  typing,required TResult orElse(),}){
final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that);case ChatEvent_MessageSent() when messageSent != null:
return messageSent(_that);case ChatEvent_MessageFailed() when messageFailed != null:
return messageFailed(_that);case ChatEvent_ReceiptReceived() when receiptReceived != null:
return receiptReceived(_that);case ChatEvent_Typing() when typing != null:
return typing(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( ChatEvent_MessageReceived value)  messageReceived,required TResult Function( ChatEvent_MessageSent value)  messageSent,required TResult Function( ChatEvent_MessageFailed value)  messageFailed,required TResult Function( ChatEvent_ReceiptReceived value)  receiptReceived,required TResult Function( ChatEvent_Typing value)  typing,}){
final _that = this;
switch (_that) {
case ChatEvent_MessageReceived():
return messageReceived(_that);case ChatEvent_MessageSent():
return messageSent(_that);case ChatEvent_MessageFailed():
return messageFailed(_that);case ChatEvent_ReceiptReceived():
return receiptReceived(_that);case ChatEvent_Typing():
return typing(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( ChatEvent_MessageReceived value)?  messageReceived,TResult? Function( ChatEvent_MessageSent value)?  messageSent,TResult? Function( ChatEvent_MessageFailed value)?  messageFailed,TResult? Function( ChatEvent_ReceiptReceived value)?  receiptReceived,TResult? Function( ChatEvent_Typing value)?  typing,}){
final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that);case ChatEvent_MessageSent() when messageSent != null:
return messageSent(_that);case ChatEvent_MessageFailed() when messageFailed != null:
return messageFailed(_that);case ChatEvent_ReceiptReceived() when receiptReceived != null:
return receiptReceived(_that);case ChatEvent_Typing() when typing != null:
return typing(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( PlatformInt64 id,  DeviceAddress from,  Uint8List body,  bool identityChanged)?  messageReceived,TResult Function( Uint8List clientMessageId)?  messageSent,TResult Function( Uint8List clientMessageId,  CoreError error)?  messageFailed,TResult Function( PlatformInt64 id,  DeviceAddress from,  ReceiptKind kind,  List<Uint8List> clientMessageIds,  BigInt serverTimestamp)?  receiptReceived,TResult Function( DeviceAddress from,  bool started,  BigInt serverTimestamp)?  typing,required TResult orElse(),}) {final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that.id,_that.from,_that.body,_that.identityChanged);case ChatEvent_MessageSent() when messageSent != null:
return messageSent(_that.clientMessageId);case ChatEvent_MessageFailed() when messageFailed != null:
return messageFailed(_that.clientMessageId,_that.error);case ChatEvent_ReceiptReceived() when receiptReceived != null:
return receiptReceived(_that.id,_that.from,_that.kind,_that.clientMessageIds,_that.serverTimestamp);case ChatEvent_Typing() when typing != null:
return typing(_that.from,_that.started,_that.serverTimestamp);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( PlatformInt64 id,  DeviceAddress from,  Uint8List body,  bool identityChanged)  messageReceived,required TResult Function( Uint8List clientMessageId)  messageSent,required TResult Function( Uint8List clientMessageId,  CoreError error)  messageFailed,required TResult Function( PlatformInt64 id,  DeviceAddress from,  ReceiptKind kind,  List<Uint8List> clientMessageIds,  BigInt serverTimestamp)  receiptReceived,required TResult Function( DeviceAddress from,  bool started,  BigInt serverTimestamp)  typing,}) {final _that = this;
switch (_that) {
case ChatEvent_MessageReceived():
return messageReceived(_that.id,_that.from,_that.body,_that.identityChanged);case ChatEvent_MessageSent():
return messageSent(_that.clientMessageId);case ChatEvent_MessageFailed():
return messageFailed(_that.clientMessageId,_that.error);case ChatEvent_ReceiptReceived():
return receiptReceived(_that.id,_that.from,_that.kind,_that.clientMessageIds,_that.serverTimestamp);case ChatEvent_Typing():
return typing(_that.from,_that.started,_that.serverTimestamp);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( PlatformInt64 id,  DeviceAddress from,  Uint8List body,  bool identityChanged)?  messageReceived,TResult? Function( Uint8List clientMessageId)?  messageSent,TResult? Function( Uint8List clientMessageId,  CoreError error)?  messageFailed,TResult? Function( PlatformInt64 id,  DeviceAddress from,  ReceiptKind kind,  List<Uint8List> clientMessageIds,  BigInt serverTimestamp)?  receiptReceived,TResult? Function( DeviceAddress from,  bool started,  BigInt serverTimestamp)?  typing,}) {final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that.id,_that.from,_that.body,_that.identityChanged);case ChatEvent_MessageSent() when messageSent != null:
return messageSent(_that.clientMessageId);case ChatEvent_MessageFailed() when messageFailed != null:
return messageFailed(_that.clientMessageId,_that.error);case ChatEvent_ReceiptReceived() when receiptReceived != null:
return receiptReceived(_that.id,_that.from,_that.kind,_that.clientMessageIds,_that.serverTimestamp);case ChatEvent_Typing() when typing != null:
return typing(_that.from,_that.started,_that.serverTimestamp);case _:
  return null;

}
}

}

/// @nodoc


class ChatEvent_MessageReceived extends ChatEvent {
  const ChatEvent_MessageReceived({required this.id, required this.from, required this.body, required this.identityChanged}): super._();
  

/// Id da mensagem no banco, o mesmo de [`ReceivedMessage::id`].
 final  PlatformInt64 id;
/// Dispositivo que enviou, conforme o certificado de remetente.
 final  DeviceAddress from;
/// Texto decifrado.
 final  Uint8List body;
/// A chave de identidade da conta de `from` mudou nesta mensagem: o código de segurança
/// da conversa é outro. O app mostra o aviso neste ponto da conversa; se a conversa
/// estava verificada, o envio fica bloqueado até o usuário agir
/// ([`super::FalaaiCore::set_identity_verified`]).
 final  bool identityChanged;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$ChatEvent_MessageReceivedCopyWith<ChatEvent_MessageReceived> get copyWith => _$ChatEvent_MessageReceivedCopyWithImpl<ChatEvent_MessageReceived>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ChatEvent_MessageReceived&&(identical(other.id, id) || other.id == id)&&(identical(other.from, from) || other.from == from)&&const DeepCollectionEquality().equals(other.body, body)&&(identical(other.identityChanged, identityChanged) || other.identityChanged == identityChanged));
}


@override
int get hashCode => Object.hash(runtimeType,id,from,const DeepCollectionEquality().hash(body),identityChanged);

@override
String toString() {
  return 'ChatEvent.messageReceived(id: $id, from: $from, body: $body, identityChanged: $identityChanged)';
}


}

/// @nodoc
abstract mixin class $ChatEvent_MessageReceivedCopyWith<$Res> implements $ChatEventCopyWith<$Res> {
  factory $ChatEvent_MessageReceivedCopyWith(ChatEvent_MessageReceived value, $Res Function(ChatEvent_MessageReceived) _then) = _$ChatEvent_MessageReceivedCopyWithImpl;
@useResult
$Res call({
 PlatformInt64 id, DeviceAddress from, Uint8List body, bool identityChanged
});




}
/// @nodoc
class _$ChatEvent_MessageReceivedCopyWithImpl<$Res>
    implements $ChatEvent_MessageReceivedCopyWith<$Res> {
  _$ChatEvent_MessageReceivedCopyWithImpl(this._self, this._then);

  final ChatEvent_MessageReceived _self;
  final $Res Function(ChatEvent_MessageReceived) _then;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? id = null,Object? from = null,Object? body = null,Object? identityChanged = null,}) {
  return _then(ChatEvent_MessageReceived(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as PlatformInt64,from: null == from ? _self.from : from // ignore: cast_nullable_to_non_nullable
as DeviceAddress,body: null == body ? _self.body : body // ignore: cast_nullable_to_non_nullable
as Uint8List,identityChanged: null == identityChanged ? _self.identityChanged : identityChanged // ignore: cast_nullable_to_non_nullable
as bool,
  ));
}


}

/// @nodoc


class ChatEvent_MessageSent extends ChatEvent {
  const ChatEvent_MessageSent({required this.clientMessageId}): super._();
  

/// O id que `send_message` devolveu.
 final  Uint8List clientMessageId;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$ChatEvent_MessageSentCopyWith<ChatEvent_MessageSent> get copyWith => _$ChatEvent_MessageSentCopyWithImpl<ChatEvent_MessageSent>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ChatEvent_MessageSent&&const DeepCollectionEquality().equals(other.clientMessageId, clientMessageId));
}


@override
int get hashCode => Object.hash(runtimeType,const DeepCollectionEquality().hash(clientMessageId));

@override
String toString() {
  return 'ChatEvent.messageSent(clientMessageId: $clientMessageId)';
}


}

/// @nodoc
abstract mixin class $ChatEvent_MessageSentCopyWith<$Res> implements $ChatEventCopyWith<$Res> {
  factory $ChatEvent_MessageSentCopyWith(ChatEvent_MessageSent value, $Res Function(ChatEvent_MessageSent) _then) = _$ChatEvent_MessageSentCopyWithImpl;
@useResult
$Res call({
 Uint8List clientMessageId
});




}
/// @nodoc
class _$ChatEvent_MessageSentCopyWithImpl<$Res>
    implements $ChatEvent_MessageSentCopyWith<$Res> {
  _$ChatEvent_MessageSentCopyWithImpl(this._self, this._then);

  final ChatEvent_MessageSent _self;
  final $Res Function(ChatEvent_MessageSent) _then;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? clientMessageId = null,}) {
  return _then(ChatEvent_MessageSent(
clientMessageId: null == clientMessageId ? _self.clientMessageId : clientMessageId // ignore: cast_nullable_to_non_nullable
as Uint8List,
  ));
}


}

/// @nodoc


class ChatEvent_MessageFailed extends ChatEvent {
  const ChatEvent_MessageFailed({required this.clientMessageId, required this.error}): super._();
  

/// O id que `send_message` devolveu.
 final  Uint8List clientMessageId;
/// Por quê: [`CoreError::SessionNotFound`], [`CoreError::UntrustedIdentity`],
/// [`CoreError::UnknownDestination`] ou [`CoreError::InvalidEnvelope`].
 final  CoreError error;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$ChatEvent_MessageFailedCopyWith<ChatEvent_MessageFailed> get copyWith => _$ChatEvent_MessageFailedCopyWithImpl<ChatEvent_MessageFailed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ChatEvent_MessageFailed&&const DeepCollectionEquality().equals(other.clientMessageId, clientMessageId)&&(identical(other.error, error) || other.error == error));
}


@override
int get hashCode => Object.hash(runtimeType,const DeepCollectionEquality().hash(clientMessageId),error);

@override
String toString() {
  return 'ChatEvent.messageFailed(clientMessageId: $clientMessageId, error: $error)';
}


}

/// @nodoc
abstract mixin class $ChatEvent_MessageFailedCopyWith<$Res> implements $ChatEventCopyWith<$Res> {
  factory $ChatEvent_MessageFailedCopyWith(ChatEvent_MessageFailed value, $Res Function(ChatEvent_MessageFailed) _then) = _$ChatEvent_MessageFailedCopyWithImpl;
@useResult
$Res call({
 Uint8List clientMessageId, CoreError error
});




}
/// @nodoc
class _$ChatEvent_MessageFailedCopyWithImpl<$Res>
    implements $ChatEvent_MessageFailedCopyWith<$Res> {
  _$ChatEvent_MessageFailedCopyWithImpl(this._self, this._then);

  final ChatEvent_MessageFailed _self;
  final $Res Function(ChatEvent_MessageFailed) _then;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? clientMessageId = null,Object? error = null,}) {
  return _then(ChatEvent_MessageFailed(
clientMessageId: null == clientMessageId ? _self.clientMessageId : clientMessageId // ignore: cast_nullable_to_non_nullable
as Uint8List,error: null == error ? _self.error : error // ignore: cast_nullable_to_non_nullable
as CoreError,
  ));
}


}

/// @nodoc


class ChatEvent_ReceiptReceived extends ChatEvent {
  const ChatEvent_ReceiptReceived({required this.id, required this.from, required this.kind, required final  List<Uint8List> clientMessageIds, required this.serverTimestamp}): _clientMessageIds = clientMessageIds,super._();
  

/// Id do recibo no banco, o mesmo de [`ReceivedReceipt::id`].
 final  PlatformInt64 id;
/// Dispositivo que confirma, conforme o certificado de remetente.
 final  DeviceAddress from;
/// Entrega ou leitura.
 final  ReceiptKind kind;
/// Os ids que [`super::FalaaiCore::send_message`] devolveu para as mensagens
/// confirmadas.
 final  List<Uint8List> _clientMessageIds;
/// Os ids que [`super::FalaaiCore::send_message`] devolveu para as mensagens
/// confirmadas.
 List<Uint8List> get clientMessageIds {
  if (_clientMessageIds is EqualUnmodifiableListView) return _clientMessageIds;
  // ignore: implicit_dynamic_type
  return EqualUnmodifiableListView(_clientMessageIds);
}

/// Instante em que o servidor recebeu o recibo, em milissegundos desde a época Unix.
 final  BigInt serverTimestamp;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$ChatEvent_ReceiptReceivedCopyWith<ChatEvent_ReceiptReceived> get copyWith => _$ChatEvent_ReceiptReceivedCopyWithImpl<ChatEvent_ReceiptReceived>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ChatEvent_ReceiptReceived&&(identical(other.id, id) || other.id == id)&&(identical(other.from, from) || other.from == from)&&(identical(other.kind, kind) || other.kind == kind)&&const DeepCollectionEquality().equals(other._clientMessageIds, _clientMessageIds)&&(identical(other.serverTimestamp, serverTimestamp) || other.serverTimestamp == serverTimestamp));
}


@override
int get hashCode => Object.hash(runtimeType,id,from,kind,const DeepCollectionEquality().hash(_clientMessageIds),serverTimestamp);

@override
String toString() {
  return 'ChatEvent.receiptReceived(id: $id, from: $from, kind: $kind, clientMessageIds: $clientMessageIds, serverTimestamp: $serverTimestamp)';
}


}

/// @nodoc
abstract mixin class $ChatEvent_ReceiptReceivedCopyWith<$Res> implements $ChatEventCopyWith<$Res> {
  factory $ChatEvent_ReceiptReceivedCopyWith(ChatEvent_ReceiptReceived value, $Res Function(ChatEvent_ReceiptReceived) _then) = _$ChatEvent_ReceiptReceivedCopyWithImpl;
@useResult
$Res call({
 PlatformInt64 id, DeviceAddress from, ReceiptKind kind, List<Uint8List> clientMessageIds, BigInt serverTimestamp
});




}
/// @nodoc
class _$ChatEvent_ReceiptReceivedCopyWithImpl<$Res>
    implements $ChatEvent_ReceiptReceivedCopyWith<$Res> {
  _$ChatEvent_ReceiptReceivedCopyWithImpl(this._self, this._then);

  final ChatEvent_ReceiptReceived _self;
  final $Res Function(ChatEvent_ReceiptReceived) _then;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? id = null,Object? from = null,Object? kind = null,Object? clientMessageIds = null,Object? serverTimestamp = null,}) {
  return _then(ChatEvent_ReceiptReceived(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as PlatformInt64,from: null == from ? _self.from : from // ignore: cast_nullable_to_non_nullable
as DeviceAddress,kind: null == kind ? _self.kind : kind // ignore: cast_nullable_to_non_nullable
as ReceiptKind,clientMessageIds: null == clientMessageIds ? _self._clientMessageIds : clientMessageIds // ignore: cast_nullable_to_non_nullable
as List<Uint8List>,serverTimestamp: null == serverTimestamp ? _self.serverTimestamp : serverTimestamp // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class ChatEvent_Typing extends ChatEvent {
  const ChatEvent_Typing({required this.from, required this.started, required this.serverTimestamp}): super._();
  

/// Dispositivo que digita, conforme o certificado de remetente.
 final  DeviceAddress from;
/// `true` começou, `false` parou.
 final  bool started;
/// Instante em que o servidor recebeu o aviso, em milissegundos desde a época Unix.
 final  BigInt serverTimestamp;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$ChatEvent_TypingCopyWith<ChatEvent_Typing> get copyWith => _$ChatEvent_TypingCopyWithImpl<ChatEvent_Typing>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ChatEvent_Typing&&(identical(other.from, from) || other.from == from)&&(identical(other.started, started) || other.started == started)&&(identical(other.serverTimestamp, serverTimestamp) || other.serverTimestamp == serverTimestamp));
}


@override
int get hashCode => Object.hash(runtimeType,from,started,serverTimestamp);

@override
String toString() {
  return 'ChatEvent.typing(from: $from, started: $started, serverTimestamp: $serverTimestamp)';
}


}

/// @nodoc
abstract mixin class $ChatEvent_TypingCopyWith<$Res> implements $ChatEventCopyWith<$Res> {
  factory $ChatEvent_TypingCopyWith(ChatEvent_Typing value, $Res Function(ChatEvent_Typing) _then) = _$ChatEvent_TypingCopyWithImpl;
@useResult
$Res call({
 DeviceAddress from, bool started, BigInt serverTimestamp
});




}
/// @nodoc
class _$ChatEvent_TypingCopyWithImpl<$Res>
    implements $ChatEvent_TypingCopyWith<$Res> {
  _$ChatEvent_TypingCopyWithImpl(this._self, this._then);

  final ChatEvent_Typing _self;
  final $Res Function(ChatEvent_Typing) _then;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? from = null,Object? started = null,Object? serverTimestamp = null,}) {
  return _then(ChatEvent_Typing(
from: null == from ? _self.from : from // ignore: cast_nullable_to_non_nullable
as DeviceAddress,started: null == started ? _self.started : started // ignore: cast_nullable_to_non_nullable
as bool,serverTimestamp: null == serverTimestamp ? _self.serverTimestamp : serverTimestamp // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

// dart format on
