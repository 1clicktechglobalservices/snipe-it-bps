@extends('layouts/default')

{{-- Page title --}}
@section('title')

    {{ $department->name }}
    {{ trans('general.department') }}
    @parent
@stop

@section('header_right')
    <i class="fa-regular fa-2x fa-square-caret-right pull-right" id="expand-info-panel-button" data-tooltip="true" title="{{ trans('button.show_hide_info') }}"></i>
@endsection

{{-- Page content --}}
@section('content')
    <x-container columns="2">
        <x-page-column class="col-md-9 main-panel">
            <x-box>

                <x-slot:bulkactions>
                    <x-table.bulk-users />
                </x-slot:bulkactions>

                <x-table
                        show_column_search="true"
                        show_advanced_search="true"
                        fixed_right_number="1"
                        fixed_number="2"
                        buttons="licenseButtons"
                        api_url="{{ route('api.users.index', ['department_id' => $department->id]) }}"
                        :presenter="\App\Presenters\UserPresenter::dataTableLayout()"
                        export_filename="export-{{ str_slug($department->name) }}-users-{{ date('Y-m-d') }}"
                />
            </x-box>

        </x-page-column>

        <x-page-column class="col-md-3">
            <x-box>
                <x-box.info-panel :infoPanelObj="$department" img_path="{{ app('users_upload_url') }}">

                    <x-slot:before_list>

                        @can('update', \App\Models\Department::class)
                            <a href="{{ ($department->deleted_at=='') ? route('departments.edit', $department->id) : '#' }}" class="btn btn-block btn-sm btn-warning btn-social hidden-print{{ ($department->deleted_at!='') ? ' disabled' : '' }}">
                                <x-icon type="edit" />
                                {{ trans('general.update') }}
                            </a>
                        @endcan

                        @can('delete', \App\Models\Department::class)

                            @if ($department->users()->count() > 0)
                                <button class="btn btn-block btn-sm btn-danger btn-social hidden-print disabled" data-tooltip="true"  data-placement="top" data-title="{{ trans('general.cannot_be_deleted') }}">
                                    <x-icon type="delete" />
                                    {{ trans('general.delete') }}
                                </button>
                            @else
                                <button class="btn btn-block btn-sm btn-danger btn-social delete-asset" data-toggle="modal" title="{{ trans('general.delete_what', ['item'=> trans('general.department')]) }}" data-content="{{ trans('general.sure_to_delete_var', ['item' => $department->name]) }}" data-target="#dataConfirmModal" data-tooltip="true" data-icon="fa fa-trash" data-placement="top" data-title="{{ trans('general.delete_what', ['item'=> trans('general.department')]) }}" onClick="return false;">
                                    <x-icon type="delete" />
                                    {{ trans('general.delete') }}
                                </button>
                            @endif
                        @endcan

                    </x-slot:before_list>

                </x-box.info-panel>
            </x-box>
        </x-page-column>


    </x-container>

@stop

@section('moar_scripts')
    @include ('partials.bootstrap-table',
    ['exportFile' => 'departments-users-export',
    'search' => true,
    'columns' => \App\Presenters\UserPresenter::dataTableLayout()
])

@stop
