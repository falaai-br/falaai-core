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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( ChatEvent_MessageReceived value)?  messageReceived,TResult Function( ChatEvent_MessageSent value)?  messageSent,TResult Function( ChatEvent_MessageFailed value)?  messageFailed,required TResult orElse(),}){
final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that);case ChatEvent_MessageSent() when messageSent != null:
return messageSent(_that);case ChatEvent_MessageFailed() when messageFailed != null:
return messageFailed(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( ChatEvent_MessageReceived value)  messageReceived,required TResult Function( ChatEvent_MessageSent value)  messageSent,required TResult Function( ChatEvent_MessageFailed value)  messageFailed,}){
final _that = this;
switch (_that) {
case ChatEvent_MessageReceived():
return messageReceived(_that);case ChatEvent_MessageSent():
return messageSent(_that);case ChatEvent_MessageFailed():
return messageFailed(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( ChatEvent_MessageReceived value)?  messageReceived,TResult? Function( ChatEvent_MessageSent value)?  messageSent,TResult? Function( ChatEvent_MessageFailed value)?  messageFailed,}){
final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that);case ChatEvent_MessageSent() when messageSent != null:
return messageSent(_that);case ChatEvent_MessageFailed() when messageFailed != null:
return messageFailed(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( PlatformInt64 id,  DeviceAddress from,  Uint8List body,  bool identityChanged)?  messageReceived,TResult Function( Uint8List clientMessageId)?  messageSent,TResult Function( Uint8List clientMessageId,  CoreError error)?  messageFailed,required TResult orElse(),}) {final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that.id,_that.from,_that.body,_that.identityChanged);case ChatEvent_MessageSent() when messageSent != null:
return messageSent(_that.clientMessageId);case ChatEvent_MessageFailed() when messageFailed != null:
return messageFailed(_that.clientMessageId,_that.error);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( PlatformInt64 id,  DeviceAddress from,  Uint8List body,  bool identityChanged)  messageReceived,required TResult Function( Uint8List clientMessageId)  messageSent,required TResult Function( Uint8List clientMessageId,  CoreError error)  messageFailed,}) {final _that = this;
switch (_that) {
case ChatEvent_MessageReceived():
return messageReceived(_that.id,_that.from,_that.body,_that.identityChanged);case ChatEvent_MessageSent():
return messageSent(_that.clientMessageId);case ChatEvent_MessageFailed():
return messageFailed(_that.clientMessageId,_that.error);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( PlatformInt64 id,  DeviceAddress from,  Uint8List body,  bool identityChanged)?  messageReceived,TResult? Function( Uint8List clientMessageId)?  messageSent,TResult? Function( Uint8List clientMessageId,  CoreError error)?  messageFailed,}) {final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that.id,_that.from,_that.body,_that.identityChanged);case ChatEvent_MessageSent() when messageSent != null:
return messageSent(_that.clientMessageId);case ChatEvent_MessageFailed() when messageFailed != null:
return messageFailed(_that.clientMessageId,_that.error);case _:
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

// dart format on
